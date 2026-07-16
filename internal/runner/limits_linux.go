//go:build linux

package runner

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const supervisorFileLimit = 256

// ApplySupervisorLimits bounds host resources consumed by the per-run broker.
// The sandbox service receives its own systemd limits separately.
func ApplySupervisorLimits() error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("read supervisor file limit: %w", err)
	}
	if limit.Cur <= supervisorFileLimit {
		return nil
	}
	limit.Cur = supervisorFileLimit
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("bound supervisor file limit: %w", err)
	}
	return nil
}
