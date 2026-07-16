//go:build !linux

package runner

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrSandboxSeccompUnsupported reports that Forcefield has no audited
// seccomp policy for the current operating system or CPU architecture.
var ErrSandboxSeccompUnsupported = errors.New("sandbox seccomp is unsupported")

// InstallSandboxSeccomp is unavailable outside Linux. Callers must treat this
// error as fatal and must not execute an untrusted workload without an
// equivalent platform sandbox policy.
func InstallSandboxSeccomp() error {
	return fmt.Errorf("%w: %s/%s", ErrSandboxSeccompUnsupported, runtime.GOOS, runtime.GOARCH)
}
