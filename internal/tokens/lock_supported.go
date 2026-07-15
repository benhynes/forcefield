//go:build linux || darwin

package tokens

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func tryPlatformLock(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrStoreLocked
	}
	if err != nil {
		return fmt.Errorf("acquire token-store lock: %w", err)
	}
	return nil
}

func unlockPlatformFile(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("release token-store lock: %w", err)
	}
	return nil
}
