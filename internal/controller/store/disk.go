package store

import (
	"errors"
	"fmt"
)

// ErrDiskLow is returned when a growth write is refused because free space
// is below the configured low-disk threshold. Stop/delete/decommission paths
// are deliberately NOT guarded: they have priority under low-disk pressure
// (v0.8 §9.1).
var ErrDiskLow = errors.New("store: disk free space below threshold")

// SetDiskPolicy configures the low-disk guard. minFreeBytes 0 disables the
// guard. When check is nil the platform free-space implementation is used;
// tests inject a fake to simulate a full disk deterministically.
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
