package main

import (
	"bytes"
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
