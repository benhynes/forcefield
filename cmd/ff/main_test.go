package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestIdentityIP(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"identity", "--ip", "192.0.2.10"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "ip:192.0.2.10\n" {
		t.Fatalf("got %q", stdout.String())
	}
}

func TestSubcommandHelpAndPositionalArguments(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"identity", "--help"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("subcommand help error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Usage: ff identity") {
		t.Fatalf("help output = %q", stdout.String())
	}
	stdout.Reset()
	if err := run([]string{"identity", "--ip", "192.0.2.1", "garbage"}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Fatal("positional garbage was accepted")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestVersionPropagatesOutputFailure(t *testing.T) {
	t.Parallel()
	if err := run([]string{"version"}, strings.NewReader(""), errorWriter{}, io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("version output error = %v", err)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"wat"}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Fatal("unknown command succeeded")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatal("usage was not printed")
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("version was empty")
	}
}
