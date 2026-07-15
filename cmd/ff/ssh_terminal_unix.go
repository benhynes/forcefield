//go:build unix

package main

import (
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type unixSSHTerminal struct {
	session  *ssh.Session
	fd       int
	previous *term.State
	raw      bool
}

func prepareSSHTerminal(session *ssh.Session, input io.Reader, terminalType string) (sshTerminalLifecycle, error) {
	width, height := 80, 24
	file, isFile := input.(interface{ Fd() uintptr })
	fd := -1
	if isFile {
		fd = int(file.Fd())
		if currentWidth, currentHeight, err := term.GetSize(fd); err == nil && currentWidth > 0 && currentHeight > 0 {
			width, height = currentWidth, currentHeight
		}
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty(terminalType, height, width, modes); err != nil {
		return nil, err
	}
	lifecycle := &unixSSHTerminal{session: session, fd: fd}
	if fd >= 0 && term.IsTerminal(fd) {
		state, err := term.MakeRaw(fd)
		if err != nil {
			return nil, err
		}
		lifecycle.previous = state
		lifecycle.raw = true
	}
	return lifecycle, nil
}

func (terminal *unixSSHTerminal) Restore() {
	_ = terminal.restore()
}

func (terminal *unixSSHTerminal) restore() error {
	if terminal == nil || !terminal.raw || terminal.previous == nil {
		return nil
	}
	err := term.Restore(terminal.fd, terminal.previous)
	if err == nil {
		terminal.raw = false
	}
	return err
}

func (terminal *unixSSHTerminal) HandleSignal(event os.Signal) (bool, error) {
	if terminal == nil {
		return false, nil
	}
	switch event {
	case syscall.SIGWINCH:
		terminal.resize()
		return true, nil
	case syscall.SIGTSTP:
		if err := terminal.restore(); err != nil {
			return true, err
		}
		// SIGTSTP is caught so the terminal can be restored first. SIGSTOP
		// performs the actual job-control stop without changing global signal
		// handlers; execution resumes here after the shell sends SIGCONT.
		if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
			return true, err
		}
		if terminal.previous != nil {
			if _, err := term.MakeRaw(terminal.fd); err != nil {
				return true, err
			}
			terminal.raw = true
		}
		terminal.resize()
		return true, nil
	default:
		return false, nil
	}
}

func (terminal *unixSSHTerminal) resize() {
	if terminal.fd < 0 {
		return
	}
	width, height, err := term.GetSize(terminal.fd)
	if err == nil && width > 0 && height > 0 {
		_ = terminal.session.WindowChange(height, width)
	}
}

func watchSSHSignals(events chan<- os.Signal, terminal bool) func() {
	signals := []os.Signal{os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT}
	if terminal {
		signals = append(signals, syscall.SIGWINCH, syscall.SIGTSTP)
	}
	signal.Notify(events, signals...)
	var once sync.Once
	return func() { once.Do(func() { signal.Stop(events) }) }
}

func sshTerminationExitCode(event os.Signal) (int, bool) {
	switch event {
	case syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM:
		return 128 + int(event.(syscall.Signal)), true
	default:
		return 0, false
	}
}
