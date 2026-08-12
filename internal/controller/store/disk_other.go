//go:build !linux && !windows

package store

import "errors"

// DiskFreeBytes is unsupported on platforms without a free-space syscall
// wrapper. A nil check function keeps the low-disk guard disabled rather than
// failing writes closed on an unavailable metric.
func DiskFreeBytes(string) (uint64, error) {
	return 0, errors.New("store: disk free check not implemented on this platform")
}
