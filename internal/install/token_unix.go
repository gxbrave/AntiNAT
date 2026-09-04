//go:build !windows

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func openInstallerTTY() (*os.File, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		return file, nil
	}
	if termFD := int(os.Stdin.Fd()); termFD >= 0 && termIsTerminal(termFD) {
		return os.Stdin, nil
	}
	return nil, errors.New("interactive token input requires a TTY")
}

func termIsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}

func openDescriptorToken(fd int) (*TokenInput, error) {
	if fd < 3 {
		return nil, tokenError(errors.New("token fd must be >= 3"))
	}
	// The caller owns the descriptor passed through the CLI. Use a private
	// descriptor for the TokenInput lifecycle so a caller-side *os.File cannot
	// later close a recycled descriptor number behind our back.
	ownedFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, tokenError(fmt.Errorf("duplicate token fd: %w", err))
	}
	file := os.NewFile(uintptr(ownedFD), "antinat-enrollment-token-fd")
	if file == nil {
		_ = unix.Close(ownedFD)
		return nil, tokenError(errors.New("token fd is invalid"))
	}
	token, err := readTokenBytes(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &TokenInput{
		token: token,
		close: file.Close,
	}, nil
}

func openProtectedTokenFile(path string) (*TokenInput, error) {
	if path == "" || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, tokenError(errors.New("token file path is invalid"))
	}
	parentPath := filepath.Dir(path)
	base := filepath.Base(path)
	dirFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, tokenError(fmt.Errorf("open token parent: %w", err))
	}
	parent := os.NewFile(uintptr(dirFD), "antinat-token-parent")
	if parent == nil {
		_ = unix.Close(dirFD)
		return nil, tokenError(errors.New("token parent descriptor is invalid"))
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = parent.Close()
		}
	}()
	var parentStat unix.Stat_t
	if err := unix.Fstat(dirFD, &parentStat); err != nil || !secureTokenParent(&parentStat) {
		return nil, tokenError(errors.New("token parent is not a private directory"))
	}
	tokenFD, err := unix.Openat(dirFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, tokenError(fmt.Errorf("open token file: %w", err))
	}
	file := os.NewFile(uintptr(tokenFD), "antinat-enrollment-token-file")
	if file == nil {
		_ = unix.Close(tokenFD)
		return nil, tokenError(errors.New("token file descriptor is invalid"))
	}
	var tokenStat unix.Stat_t
	if err := unix.Fstat(tokenFD, &tokenStat); err != nil || !secureTokenFile(&tokenStat) {
		_ = file.Close()
		return nil, tokenError(errors.New("token file must be a regular owner-only 0600 file"))
	}
	token, err := readTokenBytes(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	dev, ino := uint64(tokenStat.Dev), uint64(tokenStat.Ino)
	closeParent = false
	input := &TokenInput{token: token, path: path}
	input.close = func() error {
		var first error
		if err := file.Close(); err != nil {
			first = err
		}
		if err := parent.Close(); err != nil && first == nil {
			first = err
		}
		return first
	}
	input.commit = func() error {
		var current unix.Stat_t
		if err := unix.Fstatat(int(parent.Fd()), base, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			!secureTokenFile(&current) || uint64(current.Dev) != dev || uint64(current.Ino) != ino {
			return tokenError(errors.New("token file was replaced before consumption"))
		}
		if err := unix.Unlinkat(int(parent.Fd()), base, 0); err != nil {
			return tokenError(fmt.Errorf("consume token file: %w", err))
		}
		if err := unix.Fsync(int(parent.Fd())); err != nil {
			return tokenError(fmt.Errorf("sync token parent: %w", err))
		}
		return nil
	}
	return input, nil
}

func secureTokenParent(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Mode&0o022 == 0 && uint64(stat.Uid) == uint64(os.Geteuid())
}

func secureTokenFile(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 && uint64(stat.Uid) == uint64(os.Geteuid()) && stat.Nlink == 1
}

// Keep io imported in this file's compilation unit for older x/sys versions
// whose os.File.Read implementation is not used by all build configurations.
var _ = io.LimitReader
