//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package secrets

import (
	"os"
	"os/exec"
	"syscall"
)

// configureCommand puts the helper in its own process group so a timeout kills
// both a script wrapper and children such as macOS security(1). A malicious
// child can deliberately leave the group; the helper itself remains trusted.
func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
}
