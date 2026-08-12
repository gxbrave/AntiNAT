//go:build linux

package store

import (
	"fmt"
	"syscall"
)

// DiskFreeBytes returns free bytes on the filesystem containing path.
func DiskFreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("store: statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}
