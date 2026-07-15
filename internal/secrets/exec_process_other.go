//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package secrets

import "os/exec"

// CommandContext's default cancellation kills the helper on platforms where
// the standard library does not expose Unix process groups.
func configureCommand(_ *exec.Cmd) {}
