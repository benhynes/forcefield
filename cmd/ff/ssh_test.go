package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/sshclient"
)

func TestValidateSSHInvocationUsesStructuredModes(t *testing.T) {
	t.Parallel()
	service := capabilities.Service{SSH: &capabilities.SSHCapability{
		AllowShell: true, AllowPTY: true, MaxSessionDuration: "30m0s",
	}}
	if err := validateSSHInvocation(service, false, true); err != nil {
		t.Fatalf("granted shell and PTY: %v", err)
	}
	if err := validateSSHInvocation(service, true, false); err == nil || strings.Contains(err.Error(), "command-value") {
		t.Fatalf("ungranted exec error = %v", err)
	}
	service.SSH.AllowShell = false
	service.SSH.AllowExec = true
	service.SSH.AllowPTY = false
	if err := validateSSHInvocation(service, true, false); err != nil {
		t.Fatalf("granted exec: %v", err)
	}
	if err := validateSSHInvocation(service, false, false); err == nil {
		t.Fatal("ungranted shell was accepted")
	}
	if err := validateSSHInvocation(service, true, true); err == nil {
		t.Fatal("ungranted PTY was accepted")
	}
	if err := validateSSHInvocation(capabilities.Service{}, false, false); !errors.Is(err, sshclient.ErrConnection) {
		t.Fatalf("missing structured capability error = %v", err)
	}
}

func TestSSHStartFailureNeverReturnsCommandText(t *testing.T) {
	t.Parallel()
	const secretCommand = "rotate --password model-visible-secret"
	err := sshStartResult(fmt.Errorf("ssh: command %s failed", secretCommand))
	if !errors.Is(err, sshclient.ErrConnection) || strings.Contains(err.Error(), secretCommand) {
		t.Fatalf("start error was not scrubbed: %v", err)
	}
}

type fakeSSHExitError struct{ status int }

func (err fakeSSHExitError) Error() string   { return "remote exit" }
func (err fakeSSHExitError) ExitStatus() int { return err.status }

func TestSSHWaitResultPreservesRemoteStatusSilently(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		status int
		want   int
	}{{42, 42}, {255, 255}, {0, 255}, {256, 255}, {-1, 255}} {
		err := sshWaitResult(fmt.Errorf("wrapped: %w", fakeSSHExitError{status: test.status}))
		code, silent := commandExitBehavior(err)
		if code != test.want || !silent {
			t.Fatalf("status %d => (%d, %v), want (%d, true); err=%v", test.status, code, silent, test.want, err)
		}
	}
	if err := sshWaitResult(errors.New("transport included internals")); !errors.Is(err, sshclient.ErrConnection) {
		t.Fatalf("transport error was not generic: %v", err)
	}
	if err := sshWaitResult(nil); err != nil {
		t.Fatalf("successful wait = %v", err)
	}
}

func TestSSHConnectionFailureUsesConventionalExit255(t *testing.T) {
	t.Parallel()
	err := sshCLIResult(fmt.Errorf("wrapped: %w", sshclient.ErrConnection))
	code, silent := commandExitBehavior(err)
	if code != 255 || silent || !errors.Is(err, sshclient.ErrConnection) || strings.Contains(err.Error(), "wrapped") {
		t.Fatalf("connection failure => code=%d silent=%v err=%v", code, silent, err)
	}
}

func TestFindSSHServiceRequiresStructuredCapability(t *testing.T) {
	t.Parallel()
	manifest := capabilities.Manifest{Services: []capabilities.Service{
		{Name: "missing-details", Adapter: config.AdapterSSHSession, BaseURL: "https://forcefield.example/ssh/missing"},
		{Name: "infra", Adapter: config.AdapterSSHSession, BaseURL: "https://forcefield.example/ssh/infra", SSH: &capabilities.SSHCapability{AllowExec: true, MaxSessionDuration: "30m0s"}},
	}}
	if _, ok := findSSHService(manifest, "missing-details"); ok {
		t.Fatal("SSH service without structured capability was accepted")
	}
	if service, ok := findSSHService(manifest, "infra"); !ok || service.SSH == nil || !service.SSH.AllowExec {
		t.Fatalf("structured SSH service = (%#v, %v)", service, ok)
	}
}
