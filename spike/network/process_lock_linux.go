//go:build linux

package network

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	ErrInstanceLocked  = errors.New("another agent process owns the instance lock")
	ErrInvalidLockPath = errors.New("lock path must resolve to a regular file without replacement")
)

// ProcessLock keeps the flock file descriptor alive for the process lifetime.
// The path is never unlinked on close. O_NOFOLLOW, regular-file checks, and an
// inode comparison prevent symlink traversal and replacement during acquire.
type ProcessLock struct {
	file *os.File
	once sync.Once
	err  error
}

func AcquireProcessLock(path string) (*ProcessLock, error) {
	if path == "" {
		return nil, ErrInvalidLockPath
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 || !ownedByCurrentUser(parent) {
		return nil, ErrInvalidLockPath
	}
	before, beforeErr := os.Lstat(path)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, beforeErr
	}
	flags := os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrInvalidLockPath
		}
		return nil, err
	}
	closeOnError := func(closeErr error) (*ProcessLock, error) {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, closeErr
	}
	info, err := file.Stat()
	if err != nil {
		return closeOnError(err)
	}
	if !info.Mode().IsRegular() || !sameLockFile(before, beforeErr, info) {
		return closeOnError(ErrInvalidLockPath)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInstanceLocked
		}
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !sameLockFile(after, err, info) {
		if err == nil {
			err = ErrInvalidLockPath
		}
		return closeOnError(errors.Join(ErrInvalidLockPath, err))
	}
	// Do not truncate a caller-selected path. The PID marker is advisory; the
	// lock is the open inode and stale suffix bytes are intentionally ignored.
	marker := fmt.Sprintf("pid=%-16d\n", os.Getpid())
	if _, err := file.WriteAt([]byte(marker), 0); err != nil {
		return closeOnError(err)
	}
	return &ProcessLock{file: file}, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func sameLockFile(before os.FileInfo, beforeErr error, after os.FileInfo) bool {
	if beforeErr != nil {
		return errors.Is(beforeErr, os.ErrNotExist)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return beforeOK && afterOK && beforeStat.Dev == afterStat.Dev && beforeStat.Ino == afterStat.Ino
}

func (lock *ProcessLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	lock.once.Do(func() {
		unlockError := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		lock.err = errors.Join(unlockError, lock.file.Close())
	})
	return lock.err
}
