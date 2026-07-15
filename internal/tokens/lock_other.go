//go:build !linux && !darwin

package tokens

import "os"

func tryPlatformLock(*os.File) error {
	return ErrLockUnsupported
}

func unlockPlatformFile(*os.File) error {
	return nil
}
