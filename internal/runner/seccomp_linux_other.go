//go:build linux && !amd64 && !arm64

package runner

import (
	"fmt"
	"runtime"
)

func sandboxSeccompArchitecture() (sandboxSeccompSpec, error) {
	return sandboxSeccompSpec{}, fmt.Errorf("%w: linux/%s", ErrSandboxSeccompUnsupported, runtime.GOARCH)
}
