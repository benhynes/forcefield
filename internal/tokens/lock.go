package tokens

import (
	"errors"
	"fmt"
	"os"
)

type storeLock struct {
	file *os.File
}

func acquireStoreLock(path string) (*storeLock, error) {
	if err := inspectLockDestination(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open token-store lock: %w", err)
	}
	closeOnError := func(err error) (*storeLock, error) {
		_ = file.Close()
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return closeOnError(fmt.Errorf("inspect token-store lock: %w", err))
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return closeOnError(fmt.Errorf("%w: %s", ErrSymlink, path))
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm() != 0o600 {
		return closeOnError(fmt.Errorf("%w: token-store lock must be a 0600 regular file", ErrInsecurePermissions))
	}
	if err := ensureCurrentOwner(pathInfo, "token-store lock"); err != nil {
		return closeOnError(err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("stat token-store lock: %w", err))
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return closeOnError(fmt.Errorf("%w: token-store lock changed while opening", ErrSymlink))
	}
	if err := tryPlatformLock(file); err != nil {
		return closeOnError(err)
	}
	return &storeLock{file: file}, nil
}

func inspectLockDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect token-store lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: token-store lock must be a 0600 regular file", ErrInsecurePermissions)
	}
	return ensureCurrentOwner(info, "token-store lock")
}

func (l *storeLock) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := unlockPlatformFile(file)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}
