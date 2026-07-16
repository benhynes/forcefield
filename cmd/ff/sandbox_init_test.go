package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestSandboxInitRejectsMissingAndRelativeCommand(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		nil,
		{"--socket", "/run/forcefield/broker.sock", "--listen", "127.0.0.1:7902"},
		{"--socket", "/run/forcefield/broker.sock", "--listen", "127.0.0.1:7902", "--", "codex"},
	} {
		if err := runSandboxInit(arguments, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments were accepted: %#v", arguments)
		}
	}
}

func TestBindSandboxRelayEnvironmentUsesAllocatedAddress(t *testing.T) {
	t.Setenv("FORCEFIELD_URL", "http://127.0.0.1:0")
	t.Setenv("HIVE_ADDR", "http://127.0.0.1:0"+"/.forcefield-runner/hive")
	if err := bindSandboxRelayEnvironment("127.0.0.1:43210"); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("FORCEFIELD_URL"); got != "http://127.0.0.1:43210" {
		t.Fatalf("FORCEFIELD_URL = %q", got)
	}
	if got := os.Getenv("HIVE_ADDR"); got != "http://127.0.0.1:43210/.forcefield-runner/hive" {
		t.Fatalf("HIVE_ADDR = %q", got)
	}
}
