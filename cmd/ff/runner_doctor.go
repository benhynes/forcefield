package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/runner"
)

type doctorReport struct {
	output io.Writer
	failed bool
}

func (r *doctorReport) check(name string, err error) {
	if err == nil {
		fmt.Fprintf(r.output, "PASS %s\n", name)
		return
	}
	r.failed = true
	fmt.Fprintf(r.output, "FAIL %s: %v\n", name, err)
}

func runRunner(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "doctor" {
		return errors.New("usage: ff runner doctor --profiles FILE --profile NAME --workspace DIR")
	}
	return runRunnerDoctor(args[1:], stdout, stderr)
}

func runRunnerDoctor(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("runner doctor")
	configPath := flags.String("config", "/etc/forcefield/forcefield.yaml", "same-host Forcefield configuration")
	profilesPath := flags.String("profiles", "/etc/forcefield/forcefield-runner.yaml", "runner profiles file")
	profileName := flags.String("profile", "", "runner profile name")
	workspacePath := flags.String("workspace", "", "host workspace to validate")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *profileName == "" || *workspacePath == "" {
		return errors.New("profile and workspace are required")
	}

	report := &doctorReport{output: stdout}
	report.check("Linux host", doctorLinux())
	report.check("systemd user manager", doctorSystemdUser())
	report.check("bubblewrap feature set", doctorBubblewrap())

	workspace, workspaceErr := canonicalRunWorkspace(*workspacePath)
	report.check("workspace", workspaceErr)
	if workspaceErr != nil {
		return doctorResult(report)
	}
	report.check("profiles file", runner.ValidateOperatorFile(*profilesPath, workspace))
	runnerConfig, configErr := runner.Load(*profilesPath)
	report.check("runner configuration", configErr)
	if configErr != nil {
		return doctorResult(report)
	}
	profile, profileErr := runnerConfig.Profile(*profileName)
	report.check("selected profile", profileErr)
	if profileErr != nil {
		return doctorResult(report)
	}
	report.check("sandbox init and workspace target", doctorRootFS(profile.RootFS, profile.WorkspaceTarget))

	operatorFiles := []string{*profilesPath}
	sensitivePaths := []string{profile.ClientKey, profile.TokenFile}
	if profile.TokenFile == "" {
		report.check("workload identity", runner.VerifyWorkloadIdentity(profile))
		report.check("Forcefield config file", runner.ValidateOperatorFile(*configPath, workspace))
		compiled, err := config.Load(*configPath)
		report.check("Forcefield configuration", err)
		if err == nil {
			operatorFiles = append(operatorFiles, *configPath)
			sensitivePaths = append(sensitivePaths, compiled.File.Server.AdminSocket, compiled.File.Server.TLSKey,
				compiled.File.State.TokenFile, compiled.File.State.AuditFile)
			if _, exists := compiled.Roles[profile.Role]; !exists {
				report.check("runner role", fmt.Errorf("unknown role %q", profile.Role))
			} else {
				report.check("runner role", nil)
			}
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := capabilities.Fetch(ctx, capabilities.ClientOptions{
			BaseURL: profile.ForcefieldURL, TokenFile: profile.TokenFile,
			CACertPath: profile.CACert, ClientCert: profile.ClientCert, ClientKey: profile.ClientKey,
			UserAgent: "forcefield-runner-doctor",
		})
		cancel()
		report.check("remote capability", err)
	}
	report.check("host isolation", runner.ValidateHostIsolation(runner.HostIsolationSpec{
		Profile: profile, Workspace: workspace, StateDirectory: runnerConfig.StateDirectory,
		RootFSDirectory: runnerConfig.RootFSDirectory, WorkspaceDirectory: runnerConfig.WorkspaceDirectory,
		ReadOnlySourceDirectories: runnerConfig.ReadOnlySourceDirectories,
		OperatorFiles:             operatorFiles, SensitivePaths: sensitivePaths,
	}))
	return doctorResult(report)
}

func doctorResult(report *doctorReport) error {
	if report.failed {
		return errors.New("runner doctor found one or more failures")
	}
	return nil
}

func doctorLinux() error {
	if runtime.GOOS != "linux" {
		return errors.New("runner requires Linux")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("%s is not an audited architecture", runtime.GOARCH)
	}
	return nil
}

func doctorSystemdUser() error {
	path := trustedHostExecutable("systemd-run")
	if path == "" {
		return errors.New("systemd-run is unavailable in /usr/bin or /bin")
	}
	command := exec.Command(path, "--user", "--quiet", "--collect", "--wait", "--pipe", "--", "/bin/true")
	command.Env = doctorSystemdEnvironment(os.Environ())
	if output, err := command.CombinedOutput(); err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return errors.New(detail)
	}
	return nil
}

func doctorBubblewrap() error {
	path := trustedHostExecutable("bwrap")
	if path == "" {
		return errors.New("bubblewrap is unavailable in /usr/bin or /bin")
	}
	output, err := exec.Command(path, "--help").CombinedOutput()
	if err != nil {
		return err
	}
	for _, required := range []string{"--unshare-all", "--unshare-user", "--disable-userns", "--share-net"} {
		if !strings.Contains(string(output), required) {
			return fmt.Errorf("bubblewrap does not support %s", required)
		}
	}
	return nil
}

func doctorRootFS(rootfs, workspaceTarget string) error {
	initPath := filepath.Join(rootfs, filepath.FromSlash(strings.TrimPrefix(sandboxFFExecutable, "/")))
	info, err := os.Stat(initPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("rootfs is missing executable /usr/local/bin/ff")
	}
	target := filepath.Join(rootfs, filepath.FromSlash(strings.TrimPrefix(workspaceTarget, "/")))
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return fmt.Errorf("rootfs is missing workspace target %s", workspaceTarget)
	}
	return nil
}

func trustedHostExecutable(name string) string {
	for _, directory := range []string{"/usr/bin", "/bin"} {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func doctorSystemdEnvironment(environment []string) []string {
	var result []string
	for _, item := range environment {
		if strings.HasPrefix(item, "XDG_RUNTIME_DIR=") || strings.HasPrefix(item, "DBUS_SESSION_BUS_ADDRESS=") {
			result = append(result, item)
		}
	}
	return result
}
