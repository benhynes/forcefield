package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/benhynes/forcefield/internal/runner"
)

type commandExitError struct {
	code int
	err  error
}

func (e commandExitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("sandbox command exited with status %d", e.code)
	}
	return e.err.Error()
}

func (e commandExitError) Unwrap() error { return e.err }
func (e commandExitError) ExitCode() int { return e.code }

// runSandboxInit executes inside the mount/PID/network namespace. It owns no
// credentials: its only additional authority is the already-mounted broker
// socket. This command is intentionally omitted from public usage text.
func runSandboxInit(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := newFlagSet("_sandbox-init")
	socket := flags.String("socket", "", "fixed broker socket")
	listen := flags.String("listen", "", "loopback relay address")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	commandArguments := flags.Args()
	if *socket == "" || *listen == "" || len(commandArguments) == 0 {
		return errors.New("sandbox init requires socket, listen address, and command")
	}
	if !filepath.IsAbs(commandArguments[0]) || filepath.Clean(commandArguments[0]) != commandArguments[0] {
		return errors.New("sandbox command must use a clean absolute executable path")
	}
	info, err := os.Stat(commandArguments[0])
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("sandbox command is not executable")
	}
	relay, err := runner.NewRelay(*listen, *socket)
	if err != nil {
		return err
	}
	defer relay.Close()
	if err := runner.InstallSandboxSeccomp(); err != nil {
		return fmt.Errorf("install sandbox syscall policy: %w", err)
	}
	relayErrors := make(chan error, 1)
	go func() { relayErrors <- relay.Serve() }()

	command := exec.Command(commandArguments[0], commandArguments[1:]...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	command.Env = os.Environ()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start sandbox command: %w", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	var waitErr error
	select {
	case waitErr = <-waited:
	case relayErr := <-relayErrors:
		if relayErr != nil {
			_, _ = fmt.Fprintf(stderr, "ff: sandbox relay stopped: %v\n", relayErr)
		}
		waitErr = stopSandboxCommand(command, waited, syscall.SIGTERM)
	case received := <-signals:
		waitErr = stopSandboxCommand(command, waited, received)
	}
	_ = relay.Close()
	if waitErr == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		code := exitError.ExitCode()
		if code < 0 {
			code = 128
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code += int(status.Signal())
			}
		}
		return commandExitError{code: code, err: waitErr}
	}
	return waitErr
}

func stopSandboxCommand(command *exec.Cmd, waited <-chan error, signal os.Signal) error {
	if command == nil || command.Process == nil {
		return errors.New("sandbox command was not started")
	}
	_ = command.Process.Signal(signal)
	select {
	case err := <-waited:
		return err
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		return <-waited
	}
}
