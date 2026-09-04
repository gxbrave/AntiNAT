//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func removeOwnedResource(root, relative string) (bool, error) {
	if err := validateRelativeResource(relative); err != nil {
		return false, err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	present, err := inspectWindowsPath(path)
	if err != nil || !present {
		return false, err
	}
	return removeWindowsPath(path)
}

func inspectWindowsPath(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := rejectWindowsReparse(path, info); err != nil {
		return false, err
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			if _, err := inspectWindowsPath(filepath.Join(path, entry.Name())); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("refusing to purge a non-regular resource")
	}
	return true, nil
}

func removeWindowsPath(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := rejectWindowsReparse(path, info); err != nil {
		return false, err
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			if _, err := removeWindowsPath(filepath.Join(path, entry.Name())); err != nil {
				return false, err
			}
		}
	} else if !info.Mode().IsRegular() {
		return false, errors.New("refusing to purge a non-regular resource")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove path: %w", err)
	}
	return true, nil
}

func ownedResourceExists(root, relative string) (bool, error) {
	if err := validateRelativeResource(relative); err != nil {
		return false, err
	}
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := rejectWindowsReparse(filepath.Join(root, filepath.FromSlash(relative)), info); err != nil {
		return true, err
	}
	return true, nil
}

func rejectWindowsReparse(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return errors.New("refusing to purge a symlink/reparse point")
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode purge path: %w", err)
	}
	attrs, err := windows.GetFileAttributes(wide)
	if err != nil {
		return fmt.Errorf("read purge path attributes: %w", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("refusing to purge a symlink/reparse point")
	}
	return nil
}
