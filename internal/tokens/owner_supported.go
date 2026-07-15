//go:build linux || darwin

package tokens

import (
	"fmt"
	"os"
	"syscall"
)

func ensureCurrentOwner(info os.FileInfo, kind string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%w: %s is not owned by the effective user", ErrInsecurePermissions, kind)
	}
	return nil
}
