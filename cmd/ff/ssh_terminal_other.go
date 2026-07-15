//go:build !unix

package main

import (
	"io"
	"os"
	"os/signal"
	"sync"

	"golang.org/x/crypto/ssh"
)

type otherSSHTerminal struct{}

func prepareSSHTerminal(session *ssh.Session, _ io.Reader, terminalType string) (sshTerminalLifecycle, error) {
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty(terminalType, 24, 80, modes); err != nil {
		return nil, err
	}
	return otherSSHTerminal{}, nil
}

func (otherSSHTerminal) Restore()                             {}
func (otherSSHTerminal) HandleSignal(os.Signal) (bool, error) { return false, nil }

func watchSSHSignals(events chan<- os.Signal, _ bool) func() {
	signal.Notify(events, os.Interrupt)
	var once sync.Once
	return func() { once.Do(func() { signal.Stop(events) }) }
}

func sshTerminationExitCode(os.Signal) (int, bool) { return 0, false }
