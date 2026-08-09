//go:build linux

package network

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

var ErrInstanceLocked = errors.New("another agent process owns the instance lock")

// ProcessLock keeps the flock file descriptor alive for the process lifetime.
// The path is never unlinked on close, avoiding inode replacement races.
type ProcessLock struct {
	file *os.File
	once sync.Once
	err  error
}

func AcquireProcessLock(path string) (*ProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInstanceLocked
		}
		return nil, err
	}
	if err := file.Truncate(0); err != nil {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, err
	}
	return &ProcessLock{file: file}, nil
}

func (lock *ProcessLock) Close() error {
	lock.once.Do(func() {
		unlockError := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		lock.err = errors.Join(unlockError, lock.file.Close())
	})
	return lock.err
}
