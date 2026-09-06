//go:build windows

package store

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// DiskFreeBytes returns free bytes on the volume containing path. Windows
// evidence is build-only until native runtime validation (P03 limitation);
// the API used is the documented GetDiskFreeSpaceExW.
func DiskFreeBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("store: windows path: %w", err)
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, fmt.Errorf("store: GetDiskFreeSpaceEx: %w", err)
	}
	return free, nil
}
