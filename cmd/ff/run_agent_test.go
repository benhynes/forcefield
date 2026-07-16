package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/runner"
	"github.com/benhynes/forcefield/internal/tokens"
)

func TestParseAgentRunOptions(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	options, done, err := parseAgentRunOptions([]string{
		"--config", "/etc/forcefield.yaml", "--profiles", "/etc/runner.yaml",
		"--profile", "worker", "--agent", "codex-2", "--workspace", "/work/codex-2",
		"--", "/usr/bin/codex", "--quiet",
	}, &output)
	if err != nil || done {
		t.Fatalf("parse = %#v, %v, %v", options, done, err)
	}
	if options.profile != "worker" || options.agent != "codex-2" || options.command[0] != "/usr/bin/codex" || options.command[1] != "--quiet" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseAgentRunOptionsRejectsUntrustedSelectors(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		{"--profile", "worker", "--agent", "@all", "--", "/usr/bin/codex"},
		{"--profile", "worker", "--agent", "codex-1", "--", "codex"},
		{"--config", "forcefield.yaml", "--profile", "worker", "--agent", "codex-1", "--", "/usr/bin/codex"},
		{"--profiles", "runner.yaml", "--profile", "worker", "--agent", "codex-1", "--", "/usr/bin/codex"},
		{"--agent", "codex-1", "--", "/usr/bin/codex"},
	} {
		if _, _, err := parseAgentRunOptions(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments were accepted: %#v", arguments)
		}
	}
}

func TestBindRunnerOrigin(t *testing.T) {
	t.Parallel()
	server := config.ServerConfig{Listen: "127.0.0.1:7902"}
	if err := bindRunnerOrigin("http://127.0.0.1:7902", server); err != nil {
		t.Fatal(err)
	}
	server.TLSCert = "/cert.pem"
	if err := bindRunnerOrigin("https://127.0.0.1:7902", server); err != nil {
		t.Fatal(err)
	}
	server.AdvertisedBaseURL = "https://forcefield.internal:7902"
	if err := bindRunnerOrigin("https://forcefield.internal:7902", server); err != nil {
		t.Fatal(err)
	}
	if err := bindRunnerOrigin("https://attacker.example", server); err == nil {
		t.Fatal("unbound Forcefield origin was accepted")
	}
	if err := bindRunnerOrigin("http://192.0.2.1:7902", config.ServerConfig{Listen: "0.0.0.0:7902"}); err == nil {
		t.Fatal("non-loopback listener without advertised origin was accepted")
	}
}

func TestGrantedServiceNamesAreUniqueAndSorted(t *testing.T) {
	t.Parallel()
	grants := []tokens.Grant{{Service: "linear"}, {Service: "github"}, {Service: "linear"}}
	if got, want := grantedServiceNames(grants), []string{"github", "linear"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("services = %#v, want %#v", got, want)
	}
}

func TestRunnerHiveOptionsRetainsTokenOutsideSandbox(t *testing.T) {
	profile := runner.Profile{Hive: runner.HiveConfig{
		URL: "http://127.0.0.1:7777", Network: "dev",
		AllowTo: []string{"lead@vm1"}, AllowKinds: []string{"msg"},
	}}
	t.Setenv("HIVE_TOKEN", "personal-message-token")
	t.Setenv("HIVE_AGENT", "worker@vm1")
	t.Setenv("HIVE_NET", "dev")
	t.Setenv("HIVE_ADDR", "http://127.0.0.1:7777/")
	t.Setenv("HIVE_CONTROL_TOKEN", "")
	options, actor, err := runnerHiveOptions(profile, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if actor != "worker@vm1" || options == nil || options.Token != "personal-message-token" || options.Config.Network != "dev" {
		t.Fatalf("Hive options = %#v actor=%q", options, actor)
	}
	t.Setenv("HIVE_CONTROL_TOKEN", "control-must-not-enter")
	if _, _, err := runnerHiveOptions(profile, "worker"); err == nil {
		t.Fatal("Hive CONTROL authority was accepted")
	}
}

func TestRunnerHiveOptionsRequiresPinnedSpawnIdentity(t *testing.T) {
	profile := runner.Profile{Hive: runner.HiveConfig{URL: "http://127.0.0.1:7777", Network: "dev"}}
	t.Setenv("HIVE_TOKEN", "personal-message-token")
	t.Setenv("HIVE_AGENT", "other@vm1")
	t.Setenv("HIVE_NET", "dev")
	t.Setenv("HIVE_ADDR", "http://127.0.0.1:7777")
	t.Setenv("HIVE_CONTROL_TOKEN", "")
	if _, _, err := runnerHiveOptions(profile, "worker"); err == nil {
		t.Fatal("mismatched Hive agent was accepted")
	}
	t.Setenv("HIVE_AGENT", "worker@vm1")
	t.Setenv("HIVE_ADDR", "https://attacker.example")
	if _, _, err := runnerHiveOptions(profile, "worker"); err == nil {
		t.Fatal("mismatched Hive origin was accepted")
	}
}

func TestWaitForAgentRunBrokerFailureAndWallTime(t *testing.T) {
	t.Parallel()
	brokerErrors := make(chan error, 1)
	brokerErrors <- errors.New("closed")
	if err, interrupted := waitForAgentRun(time.Second, make(chan error), brokerErrors); err == nil || !interrupted || !strings.Contains(err.Error(), "broker") {
		t.Fatalf("broker wait = %v, %v", err, interrupted)
	}
	if err, interrupted := waitForAgentRun(time.Millisecond, make(chan error), make(chan error)); err == nil || !interrupted || !strings.Contains(err.Error(), "wall-time") {
		t.Fatalf("wall wait = %v, %v", err, interrupted)
	}
}

func TestProcessExitCode(t *testing.T) {
	t.Parallel()
	if code, ok := processExitCode(nil); !ok || code != 0 {
		t.Fatalf("nil exit = %d, %v", code, ok)
	}
	command := exec.Command("sh", "-c", "exit 23")
	err := command.Run()
	if code, ok := processExitCode(err); !ok || code != 23 {
		t.Fatalf("process exit = %d, %v (%v)", code, ok, err)
	}
	if _, ok := processExitCode(errors.New("infrastructure")); ok {
		t.Fatal("infrastructure error was classified as a process exit")
	}
}

func TestExecuteStopAcceptsCollectedTransientUnit(t *testing.T) {
	t.Parallel()
	if err := executeStop(runner.CommandSpec{Path: "/bin/sh", Args: []string{"-c", "exit 5"}, Env: []string{}}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := executeStop(runner.CommandSpec{Path: "/bin/sh", Args: []string{"-c", "exit 1"}, Env: []string{}}, io.Discard); err == nil {
		t.Fatal("real systemctl failure was ignored")
	}
}

func TestRunHelpIncludesSandboxCommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "--help"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "/absolute/agent-command") {
		t.Fatalf("run help = %q", stderr.String())
	}
}
