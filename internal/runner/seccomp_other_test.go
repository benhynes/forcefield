//go:build !linux

package runner

import (
	"errors"
	"testing"
)

func TestInstallSandboxSeccompFailsClosedOutsideLinux(t *testing.T) {
	if err := InstallSandboxSeccomp(); !errors.Is(err, ErrSandboxSeccompUnsupported) {
		t.Fatalf("InstallSandboxSeccomp() error = %v, want ErrSandboxSeccompUnsupported", err)
	}
}
