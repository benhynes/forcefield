package runner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildSystemdScopeConstructsTransientService(t *testing.T) {
	tools := newSystemdTools(t)
	resources := validScopeResources()
	command := CommandSpec{
		Path: filepath.Join(tools.directory, "bwrap"),
		Args: []string{"--clearenv", "--", "/usr/bin/agent", "--work"},
		Env:  []string{"SHOULD_NOT=survive"},
	}
	writeScopeExecutable(t, command.Path)

	got, err := BuildSystemdScope(
		"forcefield-agent-codex-2.service",
		resources,
		command,
		[]string{
			"PATH=/untrusted/bin",
			"HOME=/home/operator",
			"LINEAR_TOKEN=must-not-survive",
			"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
			"XDG_RUNTIME_DIR=/run/user/1000",
		},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	wantArgs := []string{
		"--user",
		"--quiet",
		"--collect",
		"--wait",
		"--service-type=exec",
		"--unit=forcefield-agent-codex-2.service",
		"--property=MemoryMax=134217728",
		"--property=MemorySwapMax=0",
		"--property=TasksMax=64",
		"--property=CPUQuota=250%",
		"--property=RuntimeMaxSec=1800s",
		"--property=TimeoutStopSec=5s",
		"--property=SendSIGKILL=yes",
		"--property=LimitNOFILE=1024",
		"--property=KillMode=control-group",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateDevices=yes",
		"--pty",
		"--",
		command.Path,
		"--clearenv", "--", "/usr/bin/agent", "--work",
	}
	if got.Path != tools.systemdRun {
		t.Fatalf("Path = %q, want %q", got.Path, tools.systemdRun)
	}
	if !reflect.DeepEqual(got.Args, wantArgs) {
		t.Fatalf("Args mismatch\n got: %#v\nwant: %#v", got.Args, wantArgs)
	}
	wantEnvironment := []string{
		"XDG_RUNTIME_DIR=/run/user/1000",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
	}
	if !reflect.DeepEqual(got.Env, wantEnvironment) {
		t.Fatalf("Env = %#v, want %#v", got.Env, wantEnvironment)
	}
	for _, forbidden := range []string{"LINEAR_TOKEN", "must-not-survive", "HOME=", "PATH="} {
		if strings.Contains(strings.Join(got.Env, "\x00"), forbidden) {
			t.Fatalf("systemd client environment leaked %q", forbidden)
		}
	}
}

func TestBuildSystemdScopeRejectsUnsafeUnitResourcesAndCommand(t *testing.T) {
	tools := newSystemdTools(t)
	commandPath := filepath.Join(tools.directory, "bwrap")
	writeScopeExecutable(t, commandPath)
	baseCommand := CommandSpec{Path: commandPath, Args: []string{"--clearenv"}}
	baseResources := validScopeResources()

	tests := []struct {
		name      string
		unit      string
		resources Resources
		command   CommandSpec
	}{
		{"missing service suffix", "forcefield-agent-one", baseResources, baseCommand},
		{"wrong prefix", "other-agent-one.service", baseResources, baseCommand},
		{"empty identity", "forcefield-agent-.service", baseResources, baseCommand},
		{"unit traversal", "forcefield-agent-../one.service", baseResources, baseCommand},
		{"unit template", "forcefield-agent-one@root.service", baseResources, baseCommand},
		{"zero memory", "forcefield-agent-one.service", func() Resources { value := baseResources; value.MemoryMaxBytes = 0; return value }(), baseCommand},
		{"excessive tasks", "forcefield-agent-one.service", func() Resources { value := baseResources; value.TasksMax = maximumTasksMax + 1; return value }(), baseCommand},
		{"zero cpu", "forcefield-agent-one.service", func() Resources { value := baseResources; value.CPUQuotaPercent = 0; return value }(), baseCommand},
		{"zero wall time", "forcefield-agent-one.service", func() Resources { value := baseResources; value.WallTime = 0; return value }(), baseCommand},
		{"relative command", "forcefield-agent-one.service", baseResources, CommandSpec{Path: "bwrap"}},
		{"unclean command", "forcefield-agent-one.service", baseResources, CommandSpec{Path: "/usr/bin/../bin/bwrap"}},
		{"NUL argument", "forcefield-agent-one.service", baseResources, CommandSpec{Path: commandPath, Args: []string{"bad\x00arg"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildSystemdScope(test.unit, test.resources, test.command, nil, false); err == nil {
				t.Fatal("unsafe systemd service was accepted")
			}
		})
	}
}

func TestSystemdCommandsRejectUnsafeClientEnvironment(t *testing.T) {
	newSystemdTools(t)
	command := CommandSpec{Path: "/usr/bin/bwrap"}
	tests := [][]string{
		{"MALFORMED"},
		{"PATH=/bin", "PATH=/usr/bin"},
		{"XDG_RUNTIME_DIR=relative/run"},
		{"XDG_RUNTIME_DIR=/run/user/1000/../0"},
		{"XDG_RUNTIME_DIR=/run/user/1000\nBAD=value"},
		{"DBUS_SESSION_BUS_ADDRESS=tcp:host=127.0.0.1"},
		{"DBUS_SESSION_BUS_ADDRESS=unix:abstract=systemd"},
		{"XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/2000/bus"},
	}
	for _, environment := range tests {
		if _, err := BuildSystemdScope("forcefield-agent-one.service", validScopeResources(), command, environment, false); err == nil {
			t.Fatalf("unsafe environment was accepted: %#v", environment)
		}
		if _, err := SystemdStopCommand("forcefield-agent-one.service", environment); err == nil {
			t.Fatalf("unsafe stop environment was accepted: %#v", environment)
		}
	}
}

func TestSystemdStopCommand(t *testing.T) {
	tools := newSystemdTools(t)
	got, err := SystemdStopCommand("forcefield-agent-reviewer.service", []string{
		"XDG_RUNTIME_DIR=/run/user/1000",
		"AWS_SECRET_ACCESS_KEY=must-not-survive",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != tools.systemctl {
		t.Fatalf("Path = %q, want %q", got.Path, tools.systemctl)
	}
	if want := []string{"--user", "stop", "forcefield-agent-reviewer.service"}; !reflect.DeepEqual(got.Args, want) {
		t.Fatalf("Args = %#v, want %#v", got.Args, want)
	}
	if want := []string{"XDG_RUNTIME_DIR=/run/user/1000"}; !reflect.DeepEqual(got.Env, want) {
		t.Fatalf("Env = %#v, want %#v", got.Env, want)
	}
}

func TestSystemdMainPIDCommand(t *testing.T) {
	tools := newSystemdTools(t)
	got, err := SystemdMainPIDCommand("forcefield-agent-reviewer.service", []string{"XDG_RUNTIME_DIR=/run/user/1000"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != tools.systemctl {
		t.Fatalf("Path = %q", got.Path)
	}
	want := []string{"--user", "show", "--property=MainPID", "--value", "forcefield-agent-reviewer.service"}
	if !reflect.DeepEqual(got.Args, want) {
		t.Fatalf("Args = %#v, want %#v", got.Args, want)
	}
}

func TestSystemdCommandsRequireExecutables(t *testing.T) {
	useTrustedToolDirectories(t, t.TempDir())
	if _, err := BuildSystemdScope(
		"forcefield-agent-one.service",
		validScopeResources(),
		CommandSpec{Path: "/usr/bin/bwrap"},
		nil,
		false,
	); err == nil {
		t.Fatal("launch succeeded without systemd-run")
	}
	if _, err := SystemdStopCommand("forcefield-agent-one.service", nil); err == nil {
		t.Fatal("stop succeeded without systemctl")
	}
}

type systemdTools struct {
	directory  string
	systemdRun string
	systemctl  string
}

func newSystemdTools(t *testing.T) systemdTools {
	t.Helper()
	directory := t.TempDir()
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	systemdRun := filepath.Join(directory, "systemd-run")
	systemctl := filepath.Join(directory, "systemctl")
	writeScopeExecutable(t, systemdRun)
	writeScopeExecutable(t, systemctl)
	useTrustedToolDirectories(t, directory)
	return systemdTools{directory: directory, systemdRun: systemdRun, systemctl: systemctl}
}

func validScopeResources() Resources {
	return Resources{
		MemoryMaxBytes:  128 << 20,
		TasksMax:        64,
		CPUQuotaPercent: 250,
		WallTime:        Duration(30 * time.Minute),
	}
}

func writeScopeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}
