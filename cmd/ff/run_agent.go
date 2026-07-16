package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/control"
	"github.com/benhynes/forcefield/internal/runner"
	"github.com/benhynes/forcefield/internal/tokens"
)

const (
	runnerCleanupTimeout = 5 * time.Second
	sandboxFFExecutable  = "/usr/local/bin/ff"
)

type agentRunOptions struct {
	configPath   string
	profilesPath string
	profile      string
	agent        string
	workspace    string
	command      []string
}

func runAgent(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	options, done, err := parseAgentRunOptions(args, stderr)
	if done || err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("agent sandbox runner currently requires Linux")
	}
	if err := runner.ApplySupervisorLimits(); err != nil {
		return err
	}
	workspace, err := canonicalRunWorkspace(options.workspace)
	if err != nil {
		return err
	}
	if err := runner.ValidateOperatorFile(options.profilesPath, workspace); err != nil {
		return err
	}
	runnerConfig, err := runner.Load(options.profilesPath)
	if err != nil {
		return err
	}
	profile, err := runnerConfig.Profile(options.profile)
	if err != nil {
		return err
	}
	profileDigest, err := runner.ProfileDigest(profile)
	if err != nil {
		return err
	}
	var compiled *config.Compiled
	if profile.TokenFile == "" {
		if err := runner.VerifyWorkloadIdentity(profile); err != nil {
			return err
		}
		if err := runner.ValidateOperatorFile(options.configPath, workspace); err != nil {
			return err
		}
		compiled, err = config.Load(options.configPath)
		if err != nil {
			return err
		}
		if _, exists := compiled.Roles[profile.Role]; !exists {
			return fmt.Errorf("runner profile references unknown Forcefield role %q", profile.Role)
		}
		if profile.TokenTTL.Value() > compiled.File.Server.MaxTokenTTL.Value() {
			return errors.New("runner token_ttl exceeds the Forcefield server maximum")
		}
		if err := bindRunnerOrigin(profile.ForcefieldURL, compiled.File.Server); err != nil {
			return err
		}
	} else if err := runner.ValidateOperatorFile(profile.TokenFile, workspace); err != nil {
		return fmt.Errorf("validate runner token file: %w", err)
	}
	hiveOptions, hiveAgent, err := runnerHiveOptions(profile, options.agent)
	if err != nil {
		return err
	}
	if hiveOptions != nil {
		_ = os.Unsetenv("HIVE_TOKEN")
	}
	if err := runner.PrepareStateDirectory(runnerConfig.StateDirectory); err != nil {
		return err
	}
	if err := runner.ReconcileRunRecords(runnerConfig.StateDirectory, nil); err != nil {
		return err
	}
	sensitivePaths := []string{profile.ClientKey, profile.TokenFile}
	operatorFiles := []string{options.profilesPath}
	if compiled != nil {
		operatorFiles = append(operatorFiles, options.configPath)
		sensitivePaths = append(sensitivePaths,
			compiled.File.Server.AdminSocket,
			compiled.File.Server.TLSKey,
			compiled.File.State.TokenFile,
			compiled.File.State.AuditFile,
		)
		if compiled.File.Secrets.Type == "exec" {
			sensitivePaths = append(sensitivePaths, compiled.File.Secrets.Command)
		}
	}
	if err := runner.ValidateHostIsolation(runner.HostIsolationSpec{
		Profile: profile, Workspace: workspace, StateDirectory: runnerConfig.StateDirectory,
		RootFSDirectory: runnerConfig.RootFSDirectory, WorkspaceDirectory: runnerConfig.WorkspaceDirectory,
		ReadOnlySourceDirectories: runnerConfig.ReadOnlySourceDirectories,
		OperatorFiles:             operatorFiles, SensitivePaths: sensitivePaths,
	}); err != nil {
		return err
	}
	sandboxID, err := runner.NewSandboxID()
	if err != nil {
		return err
	}
	unit := "forcefield-agent-" + sandboxID + ".service"
	// Resolve the stop path before minting. A runner that cannot address the
	// service manager cannot promise whole-cgroup teardown.
	stopSpec, err := runner.SystemdStopCommand(unit, os.Environ())
	if err != nil {
		return err
	}
	brokerSocket := filepath.Join(runnerConfig.StateDirectory, ".broker-"+sandboxID[:16]+".sock")
	if len(brokerSocket) > 96 {
		return errors.New("runner state directory is too long for a private Unix socket")
	}
	if _, err := os.Lstat(brokerSocket); !errors.Is(err, os.ErrNotExist) {
		return errors.New("runner broker socket path is already occupied")
	}

	var (
		client   *control.Client
		issued   tokens.IssuedToken
		manifest capabilities.Manifest
	)
	if compiled != nil {
		client, err = control.NewClient(compiled.File.Server.AdminSocket)
		if err != nil {
			return err
		}
		mintContext, cancelMint := context.WithTimeout(context.Background(), runnerCleanupTimeout)
		issued, err = client.Mint(mintContext, control.MintRequest{
			Role: profile.Role, Workload: profile.Workload,
			TTLSeconds: int64(profile.TokenTTL.Value() / time.Second), AllowDelegation: false,
		})
		cancelMint()
		if err != nil {
			return err
		}
	} else {
		fetchContext, cancelFetch := context.WithTimeout(context.Background(), runnerCleanupTimeout)
		manifest, err = capabilities.Fetch(fetchContext, capabilities.ClientOptions{
			BaseURL: profile.ForcefieldURL, TokenFile: profile.TokenFile,
			CACertPath: profile.CACert, ClientCert: profile.ClientCert, ClientKey: profile.ClientKey,
			UserAgent: "forcefield-runner",
		})
		cancelFetch()
		if err != nil {
			return fmt.Errorf("fetch remote runner capabilities: %w", err)
		}
		issued.Bearer, err = capabilities.ReadBearerFile(profile.TokenFile)
		if err != nil {
			return errors.New("read remote runner capability")
		}
	}
	revoked := false
	revoke := func() error {
		if revoked || client == nil {
			return nil
		}
		revokeContext, cancel := context.WithTimeout(context.Background(), runnerCleanupTimeout)
		defer cancel()
		if err := client.Revoke(revokeContext, issued.Claims.TokenID); err != nil {
			return fmt.Errorf("revoke runner token %s: %w", issued.Claims.TokenID, err)
		}
		revoked = true
		return nil
	}
	defer func() { _ = revoke() }()

	services := grantedServiceNames(issued.Claims.Grants)
	tokenID, workload := issued.Claims.TokenID, profile.Workload
	if compiled == nil {
		services = manifestServiceNames(manifest)
		tokenID = ""
		workload = "remote-capability"
	}
	record := runner.RunRecord{
		Version: 1, SandboxID: sandboxID, Agent: options.agent, Profile: options.profile,
		ProfileDigest: profileDigest, TokenID: tokenID, Workload: workload,
		Workspace: workspace, Services: services, HiveAgent: hiveAgent, NetworkMode: runnerNetworkMode(profile), Unit: unit,
		Status: runner.RunStarting, StartedAt: time.Now().Round(0).UTC(),
	}
	finalized := false
	defer func() {
		if !finalized {
			now := time.Now().Round(0).UTC()
			record.Status, record.StoppedAt = runner.RunFailed, &now
			_ = runner.WriteRunRecord(runnerConfig.StateDirectory, record)
		}
	}()
	if err := runner.WriteRunRecord(runnerConfig.StateDirectory, record); err != nil {
		return errors.Join(err, revoke())
	}

	brokerOptions := runner.BrokerOptions{
		BaseURL: profile.ForcefieldURL, Bearer: issued.Bearer, AllowedServices: services,
		CACertPath: profile.CACert, ClientCertPath: profile.ClientCert, ClientKeyPath: profile.ClientKey,
		Hive: hiveOptions,
	}
	var broker *runner.Broker
	if compiled != nil {
		broker, err = runner.NewBroker(compiled, brokerOptions)
	} else {
		broker, err = runner.NewBrokerFromManifest(manifest, brokerOptions)
	}
	if hiveOptions != nil {
		hiveOptions.Token = ""
	}
	issued.Bearer = ""
	if err != nil {
		return errors.Join(err, revoke())
	}
	brokerClosed := false
	closeBroker := func() error {
		if brokerClosed {
			return nil
		}
		brokerClosed = true
		closeContext, cancel := context.WithTimeout(context.Background(), runnerCleanupTimeout)
		defer cancel()
		return broker.Close(closeContext)
	}
	defer func() {
		_ = closeBroker()
		_ = os.Remove(brokerSocket)
	}()
	if err := broker.ListenUnix(brokerSocket); err != nil {
		return errors.Join(err, revoke())
	}
	brokerErrors := make(chan error, 1)
	go func() {
		err := broker.Serve()
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		brokerErrors <- err
	}()

	initArguments := []string{"_sandbox-init", "--socket", profile.BrokerSocket, "--listen", profile.BrokerListen, "--"}
	initArguments = append(initArguments, options.command...)
	bubblewrap, err := runner.BuildBubblewrap(runner.LaunchSpec{
		Profile: profile, Workspace: workspace, BrokerHostSocket: brokerSocket,
		HiveAgent: hiveAgent, Executable: sandboxFFExecutable, RootFSExecutable: true,
		Arguments: initArguments, Environment: os.Environ(),
	})
	if err != nil {
		return errors.Join(err, closeBroker(), revoke())
	}
	terminal := isTerminalReader(stdin) && isTerminalWriter(stdout)
	launch, err := runner.BuildSystemdScope(unit, profile.Resources, bubblewrap, os.Environ(), terminal)
	if err != nil {
		return errors.Join(err, closeBroker(), revoke())
	}
	command := exec.Command(launch.Path, launch.Args...)
	command.Env = launch.Env
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	if err := command.Start(); err != nil {
		return errors.Join(fmt.Errorf("start runner service: %w", err), closeBroker(), revoke())
	}
	record.SupervisorPID, record.MainPID, record.Status = command.Process.Pid, querySystemdMainPID(unit, os.Environ()), runner.RunRunning
	if err := runner.WriteRunRecord(runnerConfig.StateDirectory, record); err != nil {
		closeErr, revokeErr := closeBroker(), revoke()
		stopErr := executeStop(stopSpec, stderr)
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return errors.Join(err, closeErr, revokeErr, stopErr)
	}

	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	waitErr, interrupted := waitForAgentRun(profile.Resources.WallTime.Value(), waited, brokerErrors)
	cleanupErr := errors.Join(closeBroker(), revoke(), executeStop(stopSpec, stderr))
	if interrupted {
		select {
		case commandErr := <-waited:
			if waitErr == nil {
				waitErr = commandErr
			}
		case <-time.After(runnerCleanupTimeout):
			_ = command.Process.Kill()
			commandErr := <-waited
			if waitErr == nil {
				waitErr = commandErr
			}
		}
	}

	now := time.Now().Round(0).UTC()
	record.StoppedAt = &now
	exitCode, isProcessExit := processExitCode(waitErr)
	if waitErr == nil {
		exitCode, isProcessExit = 0, true
	}
	if isProcessExit && cleanupErr == nil {
		record.Status, record.ExitCode = runner.RunExited, &exitCode
	} else {
		record.Status = runner.RunFailed
		if isProcessExit {
			record.ExitCode = &exitCode
		}
	}
	stateErr := runner.WriteRunRecord(runnerConfig.StateDirectory, record)
	finalized = true
	if cleanupErr != nil || stateErr != nil {
		return errors.Join(waitErr, cleanupErr, stateErr)
	}
	if waitErr != nil {
		if isProcessExit {
			return commandExitError{code: exitCode, err: waitErr}
		}
		return waitErr
	}
	return nil
}

func runnerNetworkMode(profile runner.Profile) string {
	if profile.ShareNetwork {
		return "host"
	}
	return "isolated"
}

func parseAgentRunOptions(args []string, output io.Writer) (agentRunOptions, bool, error) {
	flags := newFlagSet("run")
	configPath := flags.String("config", "/etc/forcefield/forcefield.yaml", "same-host mode: absolute Forcefield configuration file outside the workspace")
	profilesPath := flags.String("profiles", "/etc/forcefield/forcefield-runner.yaml", "absolute runner profiles file outside the workspace")
	profile := flags.String("profile", "", "operator-owned sandbox profile")
	agent := flags.String("agent", "", "Hive agent identity for audit correlation")
	workspace := flags.String("workspace", ".", "host workspace mounted into the sandbox")
	flags.SetOutput(output)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(output, "Usage: ff run [options] -- /absolute/agent-command [args...]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return agentRunOptions{}, true, nil
	} else if err != nil {
		return agentRunOptions{}, false, err
	}
	command := flags.Args()
	if *profile == "" || !validRunnerIdentity(*agent) {
		return agentRunOptions{}, false, errors.New("profile and a lowercase agent identity are required")
	}
	if len(command) == 0 || !filepath.IsAbs(command[0]) || filepath.Clean(command[0]) != command[0] {
		return agentRunOptions{}, false, errors.New("an absolute sandbox command is required after --")
	}
	if !filepath.IsAbs(*configPath) || filepath.Clean(*configPath) != *configPath ||
		!filepath.IsAbs(*profilesPath) || filepath.Clean(*profilesPath) != *profilesPath {
		return agentRunOptions{}, false, errors.New("config and profiles must be clean absolute paths")
	}
	return agentRunOptions{
		configPath: *configPath, profilesPath: *profilesPath, profile: *profile, agent: *agent,
		workspace: *workspace, command: append([]string(nil), command...),
	}, false, nil
}

func bindRunnerOrigin(actual string, server config.ServerConfig) error {
	expected := strings.TrimSuffix(server.AdvertisedBaseURL, "/")
	if expected == "" {
		host, port, err := net.SplitHostPort(server.Listen)
		if err != nil {
			return errors.New("runner cannot derive the local Forcefield origin")
		}
		if !runnerLoopbackHost(host) {
			return errors.New("server.advertised_base_url is required for the runner when server.listen is not loopback")
		}
		scheme := "http"
		if server.TLSCert != "" {
			scheme = "https"
		}
		expected = (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}).String()
	}
	if actual != expected {
		return errors.New("runner forcefield_url does not match server.advertised_base_url or the local listener")
	}
	return nil
}

func canonicalRunWorkspace(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve runner workspace")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.New("resolve runner workspace")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("runner workspace must be a directory")
	}
	resolved = filepath.Clean(resolved)
	protectedRoots := []string{os.Getenv("XDG_RUNTIME_DIR")}
	if current, currentErr := user.Current(); currentErr == nil {
		protectedRoots = append(protectedRoots, current.HomeDir)
	}
	for _, root := range protectedRoots {
		if root == "" {
			continue
		}
		canonicalRoot, rootErr := filepath.EvalSymlinks(root)
		if rootErr == nil && hostPathContains(resolved, filepath.Clean(canonicalRoot)) {
			return "", errors.New("runner workspace must not contain the host home or runtime directory")
		}
	}
	return resolved, nil
}

func hostPathContains(directory, candidate string) bool {
	relative, err := filepath.Rel(directory, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func runnerHiveOptions(profile runner.Profile, requestedAgent string) (*runner.HiveProxyOptions, string, error) {
	if !profile.Hive.Enabled() {
		return nil, "", nil
	}
	if os.Getenv("HIVE_CONTROL_TOKEN") != "" {
		return nil, "", errors.New("runner refuses Hive CONTROL authority; spawn the sandbox without grant_control")
	}
	token := os.Getenv("HIVE_TOKEN")
	actor := os.Getenv("HIVE_AGENT")
	if token == "" || len(token) > 4<<10 || strings.IndexFunc(token, func(current rune) bool {
		return unicode.IsSpace(current) || unicode.IsControl(current)
	}) >= 0 {
		return nil, "", errors.New("Hive-enabled runner requires a bounded personal HIVE_TOKEN")
	}
	name, host, found := strings.Cut(actor, "@")
	if !found || strings.Contains(host, "@") || name != requestedAgent || !validRunnerIdentity(name) || !validRunnerIdentity(host) || len(name) > 32 || len(host) > 32 {
		return nil, "", errors.New("HIVE_AGENT must be the requested agent's canonical name@host identity")
	}
	if network := os.Getenv("HIVE_NET"); network == "" || network != profile.Hive.Network {
		return nil, "", errors.New("HIVE_NET does not match the operator-owned runner profile")
	}
	if address := strings.TrimSuffix(os.Getenv("HIVE_ADDR"), "/"); address == "" || address != profile.Hive.URL {
		return nil, "", errors.New("HIVE_ADDR does not match the operator-owned runner profile")
	}
	return &runner.HiveProxyOptions{Config: profile.Hive, Token: token, Actor: actor}, actor, nil
}

func grantedServiceNames(grants []tokens.Grant) []string {
	seen := make(map[string]struct{}, len(grants))
	services := make([]string, 0, len(grants))
	for _, grant := range grants {
		if _, exists := seen[grant.Service]; exists {
			continue
		}
		seen[grant.Service] = struct{}{}
		services = append(services, grant.Service)
	}
	slices.Sort(services)
	return services
}

func manifestServiceNames(manifest capabilities.Manifest) []string {
	services := make([]string, 0, len(manifest.Services))
	for _, service := range manifest.Services {
		services = append(services, service.Name)
	}
	slices.Sort(services)
	return services
}

func waitForAgentRun(wallTime time.Duration, waited <-chan error, brokerErrors <-chan error) (error, bool) {
	timer := time.NewTimer(wallTime)
	defer timer.Stop()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	select {
	case err := <-waited:
		return err, false
	case err := <-brokerErrors:
		if err == nil {
			return errors.New("runner broker stopped before the sandbox"), true
		}
		return fmt.Errorf("runner broker stopped: %w", err), true
	case <-timer.C:
		return errors.New("runner wall-time limit exceeded"), true
	case received := <-signals:
		return fmt.Errorf("runner received %s", received), true
	}
}

func executeStop(spec runner.CommandSpec, stderr io.Writer) error {
	stopContext, cancel := context.WithTimeout(context.Background(), runnerCleanupTimeout)
	defer cancel()
	command := exec.CommandContext(stopContext, spec.Path, spec.Args...)
	var errorOutput bytes.Buffer
	command.Env, command.Stdin, command.Stdout, command.Stderr = spec.Env, nil, io.Discard, &errorOutput
	err := command.Run()
	if errors.Is(stopContext.Err(), context.DeadlineExceeded) {
		return errors.New("stop runner service timed out")
	}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 5 {
			// systemctl uses LSB status 5 when a transient unit is already
			// collected. That is the desired teardown state.
			return nil
		}
		if errorOutput.Len() != 0 {
			_, _ = stderr.Write(errorOutput.Bytes())
		}
		return fmt.Errorf("stop runner service: %w", err)
	}
	return nil
}

func querySystemdMainPID(unit string, environment []string) int {
	spec, err := runner.SystemdMainPIDCommand(unit, environment)
	if err != nil {
		return 0
	}
	for attempt := 0; attempt < 20; attempt++ {
		queryContext, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		command := exec.CommandContext(queryContext, spec.Path, spec.Args...)
		command.Env = spec.Env
		output, runErr := command.Output()
		cancel()
		if runErr == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
			if parseErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return 0
}

func processExitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return 0, false
	}
	code := exitError.ExitCode()
	if code < 0 {
		code = 128
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code += int(status.Signal())
		}
	}
	return code, true
}

func validRunnerIdentity(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, current := range value {
		if current >= 'a' && current <= 'z' || current >= '0' && current <= '9' || index > 0 && (current == '-' || current == '_') {
			continue
		}
		return false
	}
	return true
}

func runnerLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func isTerminalReader(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
