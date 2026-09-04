//go:build !windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func removeOwnedResource(root, relative string) (bool, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	if err := validateRelativeResource(relative); err != nil {
		return false, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open owned root: %w", err)
	}
	rootFile := os.NewFile(uintptr(fd), "antinat-purge-root")
	if rootFile == nil {
		_ = unix.Close(fd)
		return false, errors.New("owned root descriptor is invalid")
	}
	defer rootFile.Close()
	components := strings.Split(relative, string(filepath.Separator))
	present, err := inspectAt(rootFile, components)
	if err != nil || !present {
		return false, err
	}
	return removeAt(rootFile, components)
}

// inspectAt performs a complete handle-relative preflight before deletion. It
// prevents a late symlink or special file from causing an earlier child in the
// same owned directory to be removed first.
func inspectAt(parent *os.File, components []string) (bool, error) {
	if len(components) == 0 || components[0] == "" {
		return false, errors.New("empty purge path component")
	}
	name := components[0]
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	mode := stat.Mode & unix.S_IFMT
	if mode == unix.S_IFLNK {
		return false, errors.New("refusing to purge a symlink/reparse point")
	}
	if len(components) > 1 {
		if mode != unix.S_IFDIR {
			return false, fmt.Errorf("purge parent %q is not a directory", name)
		}
		childFD, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		child := os.NewFile(uintptr(childFD), "antinat-purge-preflight")
		if child == nil {
			_ = unix.Close(childFD)
			return false, errors.New("purge preflight descriptor is invalid")
		}
		defer child.Close()
		return inspectAt(child, components[1:])
	}
	if mode == unix.S_IFDIR {
		childFD, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		child := os.NewFile(uintptr(childFD), "antinat-purge-directory-preflight")
		if child == nil {
			_ = unix.Close(childFD)
			return false, errors.New("purge preflight directory descriptor is invalid")
		}
		names, err := child.Readdirnames(-1)
		if err != nil {
			_ = child.Close()
			return false, err
		}
		for _, entry := range names {
			if _, err := inspectAt(child, []string{entry}); err != nil {
				_ = child.Close()
				return false, err
			}
		}
		if err := child.Close(); err != nil {
			return false, err
		}
		return true, nil
	}
	if mode != unix.S_IFREG {
		return false, errors.New("refusing to purge a non-regular resource")
	}
	return true, nil
}

func removeAt(parent *os.File, components []string) (bool, error) {
	if len(components) == 0 || components[0] == "" {
		return false, errors.New("empty purge path component")
	}
	name := components[0]
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	mode := stat.Mode & unix.S_IFMT
	if mode == unix.S_IFLNK {
		return false, errors.New("refusing to purge a symlink/reparse point")
	}
	if len(components) > 1 {
		if mode != unix.S_IFDIR {
			return false, fmt.Errorf("purge parent %q is not a directory", name)
		}
		childFD, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		child := os.NewFile(uintptr(childFD), "antinat-purge-child")
		if child == nil {
			_ = unix.Close(childFD)
			return false, errors.New("purge child descriptor is invalid")
		}
		removed, err := removeAt(child, components[1:])
		closeErr := child.Close()
		if err != nil {
			return false, err
		}
		if closeErr != nil {
			return false, closeErr
		}
		return removed, nil
	}

	if mode == unix.S_IFDIR {
		childFD, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		child := os.NewFile(uintptr(childFD), "antinat-purge-directory")
		if child == nil {
			_ = unix.Close(childFD)
			return false, errors.New("purge directory descriptor is invalid")
		}
		names, readErr := child.Readdirnames(-1)
		if readErr != nil {
			_ = child.Close()
			return false, readErr
		}
		for _, entry := range names {
			if _, err := removeAt(child, []string{entry}); err != nil {
				_ = child.Close()
				return false, err
			}
		}
		if err := child.Close(); err != nil {
			return false, err
		}
		if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
			return false, err
		}
		return true, nil
	}
	if mode != unix.S_IFREG {
		return false, errors.New("refusing to purge a non-regular resource")
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func ownedResourceExists(root, relative string) (bool, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	if err := validateRelativeResource(relative); err != nil {
		return false, err
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, errors.New("purge residue is a symlink/reparse point")
	}
	return true, nil
}
