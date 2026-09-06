//go:build !windows

package install

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type purgeStage uint8

const purgeBeforeTerminalMove purgeStage = 1

type purgeHook func(purgeStage) error

type purgeQuarantine struct {
	parent *os.File
	dir    *os.File
	name   string
	path   string
	stat   unix.Stat_t
}

func verifyOwnershipKeyFile(path string, key []byte) error {
	raw, err := readProtectedFile(path, 4<<20, "ownership key")
	if err != nil {
		return err
	}
	if len(raw) != len(key) || !hmac.Equal(raw, key) {
		return errors.New("ownership key file does not match the supplied key")
	}
	return nil
}

// readProtectedFile opens the file with O_NOFOLLOW and validates the opened
// descriptor. The descriptor, rather than a second pathname lookup, is used
// for the read so a manifest or key replacement cannot bypass these checks.
func readProtectedFile(path string, limit int64, label string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s path is required", label)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(fd), "antinat-protected-file")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s descriptor is invalid", label)
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", label)
	}
	if stat.Mode&0o7777 != 0o600 {
		return nil, fmt.Errorf("%s must have mode 0600", label)
	}
	if stat.Nlink != 1 {
		return nil, fmt.Errorf("%s must have one link", label)
	}
	if uint32(os.Geteuid()) != stat.Uid {
		return nil, fmt.Errorf("%s is not owned by the current installer user", label)
	}
	if stat.Size < 0 || stat.Size > limit {
		return nil, fmt.Errorf("%s exceeds size limit", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds size limit", label)
	}
	return data, nil
}

func removeOwnedResource(root, relative string) (bool, error) {
	return removeOwnedResourceWithHook(root, relative, nil)
}

func removeOwnedResourceWithHook(root, relative string, hook purgeHook) (bool, error) {
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
	terminalParent := filepath.Join(root, filepath.Dir(filepath.FromSlash(relative)))
	return removeAt(rootFile, components, terminalParent, hook)
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

func removeAt(parent *os.File, components []string, terminalParent string, hook purgeHook) (bool, error) {
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
		removed, err := removeAt(child, components[1:], terminalParent, hook)
		closeErr := child.Close()
		if err != nil {
			return false, err
		}
		if closeErr != nil {
			return false, closeErr
		}
		return removed, nil
	}

	if mode != unix.S_IFDIR && mode != unix.S_IFREG {
		return false, errors.New("refusing to purge a non-regular resource")
	}

	openFlags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if mode == unix.S_IFDIR {
		openFlags |= unix.O_DIRECTORY
	}
	checkedFD, err := unix.Openat(int(parent.Fd()), name, openFlags, 0)
	if err != nil {
		return false, fmt.Errorf("open purge terminal %q: %w", name, err)
	}
	checked := os.NewFile(uintptr(checkedFD), "antinat-purge-terminal")
	if checked == nil {
		_ = unix.Close(checkedFD)
		return false, errors.New("purge terminal descriptor is invalid")
	}
	defer checked.Close()
	var checkedStat unix.Stat_t
	if err := unix.Fstat(checkedFD, &checkedStat); err != nil {
		return false, fmt.Errorf("stat purge terminal %q: %w", name, err)
	}
	if checkedStat.Dev != stat.Dev || checkedStat.Ino != stat.Ino || checkedStat.Mode&unix.S_IFMT != mode {
		return false, fmt.Errorf("purge terminal %q changed during purge", name)
	}

	quarantine, err := createPurgeQuarantine(terminalParent, uint64(checkedStat.Dev))
	if err != nil {
		return false, err
	}
	if hook != nil {
		if err := hook(purgeBeforeTerminalMove); err != nil {
			return false, errors.Join(fmt.Errorf("purge test hook: %w", err), quarantine.close(false))
		}
	}
	const quarantinedName = "resource"
	if err := unix.Renameat(int(parent.Fd()), name, int(quarantine.dir.Fd()), quarantinedName); err != nil {
		return false, errors.Join(fmt.Errorf("isolate purge terminal %q: %w", name, err), quarantine.close(false))
	}
	var movedStat unix.Stat_t
	if err := unix.Fstatat(int(quarantine.dir.Fd()), quarantinedName, &movedStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, errors.Join(fmt.Errorf("verify isolated purge terminal %q: %w", name, err), quarantine.close(true))
	}
	if movedStat.Dev != checkedStat.Dev || movedStat.Ino != checkedStat.Ino || movedStat.Mode&unix.S_IFMT != checkedStat.Mode&unix.S_IFMT {
		return false, errors.Join(
			fmt.Errorf("purge terminal %q changed during purge; replacement retained at %s", name, filepath.Join(quarantine.path, quarantinedName)),
			quarantine.close(true),
		)
	}
	if err := removeTrustedAt(quarantine.dir, quarantinedName); err != nil {
		return false, errors.Join(err, quarantine.close(true))
	}
	if err := quarantine.close(false); err != nil {
		return false, fmt.Errorf("clean purge quarantine: %w", err)
	}
	return true, nil
}

// createPurgeQuarantine finds the nearest same-filesystem ancestor which only
// the installer identity can modify. Once a terminal object is moved below
// that directory, its name can no longer be swapped by the service account.
func createPurgeQuarantine(start string, device uint64) (*purgeQuarantine, error) {
	candidate := filepath.Clean(start)
	for {
		fd, err := unix.Open(candidate, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == nil {
			parent := os.NewFile(uintptr(fd), "antinat-purge-quarantine-parent")
			if parent == nil {
				_ = unix.Close(fd)
				return nil, errors.New("purge quarantine parent descriptor is invalid")
			}
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); err != nil {
				_ = parent.Close()
				return nil, fmt.Errorf("stat purge quarantine parent: %w", err)
			}
			if uint64(stat.Dev) == device && stat.Uid == uint32(os.Geteuid()) && stat.Mode&0o022 == 0 {
				quarantine, err := mkdirPurgeQuarantine(parent, candidate)
				if err != nil {
					_ = parent.Close()
					return nil, err
				}
				return quarantine, nil
			}
			_ = parent.Close()
		}
		parentPath := filepath.Dir(candidate)
		if parentPath == candidate {
			break
		}
		candidate = parentPath
	}
	return nil, fmt.Errorf("no installer-owned quarantine directory on device %d", device)
}

func mkdirPurgeQuarantine(parent *os.File, parentPath string) (*purgeQuarantine, error) {
	for attempts := 0; attempts < 128; attempts++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, fmt.Errorf("generate purge quarantine name: %w", err)
		}
		name := ".antinat-purge-" + hex.EncodeToString(random[:])
		if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return nil, fmt.Errorf("create purge quarantine: %w", err)
		}
		fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
			return nil, fmt.Errorf("open purge quarantine: %w", err)
		}
		dir := os.NewFile(uintptr(fd), "antinat-purge-quarantine")
		if dir == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
			return nil, errors.New("purge quarantine descriptor is invalid")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = dir.Close()
			_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
			return nil, fmt.Errorf("stat purge quarantine: %w", err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o700 {
			_ = dir.Close()
			_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
			return nil, errors.New("purge quarantine has unsafe identity or permissions")
		}
		return &purgeQuarantine{parent: parent, dir: dir, name: name, path: filepath.Join(parentPath, name), stat: stat}, nil
	}
	return nil, errors.New("could not allocate a unique purge quarantine")
}

func (q *purgeQuarantine) close(retain bool) error {
	if q == nil {
		return nil
	}
	if retain {
		dirErr := q.dir.Close()
		parentErr := q.parent.Close()
		return errors.Join(dirErr, parentErr)
	}
	var namedStat unix.Stat_t
	statErr := unix.Fstatat(int(q.parent.Fd()), q.name, &namedStat, unix.AT_SYMLINK_NOFOLLOW)
	if statErr == nil && (namedStat.Dev != q.stat.Dev || namedStat.Ino != q.stat.Ino || namedStat.Mode&unix.S_IFMT != unix.S_IFDIR) {
		statErr = errors.New("purge quarantine changed before cleanup")
	}
	dirErr := q.dir.Close()
	var removeErr error
	if statErr == nil {
		removeErr = unix.Unlinkat(int(q.parent.Fd()), q.name, unix.AT_REMOVEDIR)
	}
	parentErr := q.parent.Close()
	return errors.Join(statErr, dirErr, removeErr, parentErr)
}

func removeTrustedAt(parent *os.File, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return unix.Unlinkat(int(parent.Fd()), name, 0)
	case unix.S_IFDIR:
		fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(fd), "antinat-purge-trusted-directory")
		if dir == nil {
			_ = unix.Close(fd)
			return errors.New("trusted purge directory descriptor is invalid")
		}
		names, err := dir.Readdirnames(-1)
		if err != nil {
			_ = dir.Close()
			return err
		}
		for _, entry := range names {
			if err := removeTrustedAt(dir, entry); err != nil {
				_ = dir.Close()
				return err
			}
		}
		if err := dir.Close(); err != nil {
			return err
		}
		return unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
	default:
		return errors.New("refusing to purge a non-regular resource")
	}
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
