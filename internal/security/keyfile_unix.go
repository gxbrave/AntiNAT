// Platform key-file persistence (non-Windows): owner-only 0600 atomic file.
// Windows uses DPAPI protection (keyfile_windows.go).
//go:build !windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gxbrave/AntiNAT/internal/security/framecrypto"
)

func framecryptoSign(priv []byte, msg []byte) ([]byte, error) {
	return framecrypto.Sign(priv, msg)
}

// loadKeyFile reads a key file, failing closed when permissions are not
// owner-only.
func loadKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("security: key file %s has mode %v, want owner-only", filepath.Base(path), info.Mode().Perm())
	}
	return os.ReadFile(path)
}

// writeKeyFileAtomic persists the blob via temp file + fsync + rename +
// parent-directory fsync, with mode 0600 from creation.
func writeKeyFileAtomic(path string, blob []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".node-key-*")
	if err != nil {
		return fmt.Errorf("security: create key temp: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("security: key chmod: %w", err)
	}
	if _, err := temp.Write(blob); err != nil {
		temp.Close()
		return fmt.Errorf("security: key write: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("security: key fsync: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("security: key close: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("security: key rename: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("security: key dir fsync: %w", err)
	}
	return nil
}

// syncDir fsyncs a directory so a rename inside it is durable.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
