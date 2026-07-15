//go:build unix

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestSSHTerminationExitCodes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		signal os.Signal
		code   int
	}{{syscall.SIGHUP, 129}, {syscall.SIGQUIT, 131}, {syscall.SIGTERM, 143}} {
		code, terminates := sshTerminationExitCode(test.signal)
		if !terminates || code != test.code {
			t.Fatalf("signal %v => (%d, %v), want (%d, true)", test.signal, code, terminates, test.code)
		}
	}
	if code, terminates := sshTerminationExitCode(os.Interrupt); terminates || code != 0 {
		t.Fatalf("interrupt => (%d, %v), want (0, false)", code, terminates)
	}
}

func TestUnixSSHTerminalHandlesResizeWithoutFileDescriptor(t *testing.T) {
	t.Parallel()
	terminal := &unixSSHTerminal{fd: -1}
	handled, err := terminal.HandleSignal(syscall.SIGWINCH)
	if err != nil || !handled {
		t.Fatalf("resize result = (%v, %v)", handled, err)
	}
}
