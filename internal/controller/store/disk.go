package store

import (
	"errors"
	"fmt"
	"syscall"
)

// ErrDiskLow is returned when a growth write is refused because free space
// is below the configured low-disk threshold. Stop/delete/decommission paths
// are deliberately NOT guarded: they have priority under low-disk pressure
// (v0.8 §9.1).
var ErrDiskLow = errors.New("store: disk free space below threshold")

// DiskFreeBytes returns free bytes on the filesystem containing path.
func DiskFreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("store: statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// SetDiskPolicy configures the low-disk guard. minFreeBytes 0 disables the
// guard. When check is nil the real filesystem is used; tests inject a fake
// to simulate a full disk deterministically.
func (s *Store) SetDiskPolicy(minFreeBytes uint64, check func(string) (uint64, error)) {
	s.minFreeBytes = minFreeBytes
	s.diskFree = check
	if check == nil {
		s.diskFree = DiskFreeBytes
	}
}

// checkWriteCapacity fails closed on low disk for growth writes.
func (s *Store) checkWriteCapacity() error {
	if s.minFreeBytes == 0 {
		return nil
	}
	free, err := s.diskFree(s.path)
	if err != nil {
		return fmt.Errorf("store: disk free check: %w", err)
	}
	if free < s.minFreeBytes {
		return ErrDiskLow
	}
	return nil
}
