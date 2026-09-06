//go:build !windows

package store

import (
	"errors"
	"os"
	"syscall"
)

var errLifecycleLockBusy = errors.New("store: lifecycle reservation is busy")

func tryLockFile(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errLifecycleLockBusy
		}
		return err
	}
	return nil
}

func unlockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
