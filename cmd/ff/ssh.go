package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/sshclient"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func runSSH(args []string, stdin io.Reader, stdout, stderr io.Writer) (result error) {
	defer func() { result = sshCLIResult(result) }()
	flags := newFlagSet("ssh")
	baseURL := flags.String("url", os.Getenv("FORCEFIELD_URL"), "Forcefield origin (or FORCEFIELD_URL)")
	tokenFile := flags.String("token-file", envDefault("FORCEFIELD_TOKEN_FILE", "~/.config/forcefield/token"), "0600 Forcefield bearer file")
	caCert := flags.String("ca-cert", os.Getenv("FORCEFIELD_CA_CERT"), "additional TLS CA certificate")
	clientCert := flags.String("client-cert", os.Getenv("FORCEFIELD_CLIENT_CERT"), "mTLS client certificate")
	clientKey := flags.String("client-key", os.Getenv("FORCEFIELD_CLIENT_KEY"), "mTLS client private key")
	forcePTY := flags.Bool("pty", false, "request a pseudo-terminal")
	flags.BoolVar(forcePTY, "t", false, "request a pseudo-terminal")
	disablePTY := flags.Bool("no-pty", false, "disable automatic pseudo-terminal allocation")
	flags.BoolVar(disablePTY, "T", false, "disable automatic pseudo-terminal allocation")
	allowInsecure := flags.Bool("allow-insecure", false, "allow loopback HTTP for development")
	timeout := flags.Duration("timeout", 10*time.Second, "capability, upstream, and SSH handshake timeout")
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: ff ssh [options] SERVICE [-- COMMAND ...]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	remaining := flags.Args()
	if len(remaining) == 0 {
		return errors.New("SSH service alias is required")
	}
	alias := remaining[0]
	command := remaining[1:]
	if len(command) != 0 && command[0] == "--" {
		command = command[1:]
	}
	if *forcePTY && *disablePTY {
		return errors.New("pty and no-pty cannot both be specified")
	}
	if *baseURL == "" {
		return errors.New("Forcefield URL is required")
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		return errors.New("timeout must be between 1s and 30s")
	}
	clientOptions := capabilities.ClientOptions{
		BaseURL: *baseURL, TokenFile: *tokenFile, CACertPath: *caCert,
		ClientCert: *clientCert, ClientKey: *clientKey, AllowInsecure: *allowInsecure,
		Timeout: *timeout, UserAgent: "forcefield/" + version,
	}
	manifest, err := capabilities.Fetch(context.Background(), clientOptions)
	if err != nil {
		return sshclient.ErrConnection
	}
	service, ok := findSSHService(manifest, alias)
	if !ok {
		return sshclient.ErrConnection
	}
	if err := validateSSHInvocation(service, len(command) != 0, *forcePTY); err != nil {
		return err
	}
	bearer, err := capabilities.ReadBearerFile(*tokenFile)
	if err != nil {
		return sshclient.ErrConnection
	}
	transport, err := capabilities.NewTransport(clientOptions)
	if err != nil {
		return sshclient.ErrConnection
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	client, err := sshclient.Dial(context.Background(), sshclient.Options{
		Endpoint: service.BaseURL, Bearer: bearer, Transport: transport,
		HandshakeTimeout: *timeout, UserAgent: "forcefield/" + version,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return sshclient.ErrConnection
	}
	defer session.Close()
	session.Stdin, session.Stdout, session.Stderr = stdin, stdout, stderr
	requestPTY := *forcePTY || !*disablePTY && len(command) == 0 && service.SSH.AllowPTY && inputIsTerminal(stdin)
	signalEvents := make(chan os.Signal, 8)
	stopSignals := watchSSHSignals(signalEvents, requestPTY)
	defer stopSignals()
	var terminal sshTerminalLifecycle
	if requestPTY {
		terminal, err = prepareSSHTerminal(session, stdin, sshTerm())
		if err != nil {
			return sshclient.ErrConnection
		}
		defer terminal.Restore()
	}
	started := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		var startErr error
		if len(command) == 0 {
			startErr = session.Shell()
		} else {
			startErr = session.Start(strings.Join(command, " "))
		}
		if err := sshStartResult(startErr); err != nil {
			completed <- err
			return
		}
		close(started)
		completed <- sshWaitResult(session.Wait())
	}()
	for {
		select {
		case err := <-completed:
			return err
		case event := <-signalEvents:
			if terminal != nil {
				handled, err := terminal.HandleSignal(event)
				if err != nil {
					return sshclient.ErrConnection
				}
				if handled {
					continue
				}
			}
			if code, terminates := sshTerminationExitCode(event); terminates {
				return silentCommandExit{code: code}
			}
			if event == os.Interrupt {
				select {
				case <-started:
					go func() { _ = session.Signal(ssh.SIGINT) }()
				default:
				}
			}
		}
	}
}

func validateSSHInvocation(service capabilities.Service, command, forcePTY bool) error {
	if service.SSH == nil {
		return sshclient.ErrConnection
	}
	if !command && !service.SSH.AllowShell {
		return errors.New("SSH shell access is not granted for this service")
	}
	if command && !service.SSH.AllowExec {
		return errors.New("SSH command execution is not granted for this service")
	}
	if forcePTY && !service.SSH.AllowPTY {
		return errors.New("SSH pseudo-terminal access is not granted for this service")
	}
	return nil
}

func findSSHService(manifest capabilities.Manifest, alias string) (capabilities.Service, bool) {
	for _, service := range manifest.Services {
		if service.Name == alias && service.Adapter == config.AdapterSSHSession && service.BaseURL != "" && service.SSH != nil {
			return service, true
		}
	}
	return capabilities.Service{}, false
}

type sshTerminalLifecycle interface {
	Restore()
	HandleSignal(os.Signal) (bool, error)
}

type silentCommandExit struct{ code int }

func (exit silentCommandExit) Error() string { return "remote command exited unsuccessfully" }
func (exit silentCommandExit) ExitCode() int { return exit.code }
func (silentCommandExit) Silent() bool       { return true }

type sshConnectionExit struct{}

func (sshConnectionExit) Error() string { return sshclient.ErrConnection.Error() }
func (sshConnectionExit) Unwrap() error { return sshclient.ErrConnection }
func (sshConnectionExit) ExitCode() int { return 255 }
func (sshConnectionExit) Silent() bool  { return false }

func sshCLIResult(err error) error {
	if errors.Is(err, sshclient.ErrConnection) {
		return sshConnectionExit{}
	}
	return err
}

type sshExitStatus interface {
	ExitStatus() int
}

func sshStartResult(err error) error {
	if err == nil {
		return nil
	}
	// x/crypto/ssh includes the complete command in an exec-start error.
	// Never let that value escape into harness stderr or logs.
	return sshclient.ErrConnection
}

func sshWaitResult(err error) error {
	if err == nil {
		return nil
	}
	var remote sshExitStatus
	if errors.As(err, &remote) {
		code := remote.ExitStatus()
		if code < 1 || code > 255 {
			code = 255
		}
		return silentCommandExit{code: code}
	}
	return sshclient.ErrConnection
}

func inputIsTerminal(input io.Reader) bool {
	file, ok := input.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(file.Fd()))
}

func sshTerm() string {
	value := os.Getenv("TERM")
	if value == "" || len(value) > 128 {
		return "xterm-256color"
	}
	for _, current := range value {
		if current <= 0x20 || current > 0x7e {
			return "xterm-256color"
		}
	}
	return value
}
