// P14 Story 5: Agent RECOVERY_QUARANTINE (v0.8 §7.4).
//
// After a backup restore the Agent must NOT auto-restore its last-known-good
// Forward listeners: it stays in RECOVERY_QUARANTINE until the Controller
// issues a recovery authorization. The quarantine is a state-dir marker file
// (like terminal.marker) written atomically. It is NEVER written over a
// DECOMMISSIONED terminal marker: the current terminal/uninstall marker on
// disk must never be overwritten by an old backup or by a quarantine marker.
package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// recoveryQuarantineFile is the quarantine marker filename.
const recoveryQuarantineFile = "recovery.quarantine"

// ErrQuarantineOverTerminal reports a quarantine write over a DECOMMISSIONED
// agent: the terminal marker is final and never reopens.
var ErrQuarantineOverTerminal = errors.New("localstate: cannot quarantine over a terminal DECOMMISSIONED marker")

// LoadRecoveryQuarantine reports whether the agent is in RECOVERY_QUARANTINE.
func LoadRecoveryQuarantine(dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	_, err := os.Stat(filepath.Join(dir, recoveryQuarantineFile))
	if err != nil {
		if errNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("localstate: read recovery quarantine: %w", err)
	}
	return true, nil
}

// WriteRecoveryQuarantine durably marks the agent as quarantined (atomic
// temp + fsync + rename + parent fsync). It refuses to run over a
// DECOMMISSIONED terminal marker so an old backup can never reopen a terminal
// uninstall.
func WriteRecoveryQuarantine(dir string) error {
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	marker, err := LoadMarker(dir)
	if err != nil {
		return err
	}
	if marker == MarkerDecommissioned {
		return ErrQuarantineOverTerminal
	}
	path := filepath.Join(dir, recoveryQuarantineFile)
	temporary, err := os.CreateTemp(dir, ".antinat-quarantine-*")
	if err != nil {
		return fmt.Errorf("localstate: quarantine temp: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: quarantine chmod: %w", err)
	}
	if _, err := temporary.WriteString("RECOVERY_QUARANTINE"); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: quarantine write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: quarantine fsync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("localstate: quarantine close: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("localstate: quarantine rename: %w", err)
	}
	return syncDirectory(dir)
}

// ClearRecoveryQuarantine removes the quarantine marker upon Controller
// recovery authorization. Idempotent.
func ClearRecoveryQuarantine(dir string) error {
	path := filepath.Join(dir, recoveryQuarantineFile)
	if err := os.Remove(path); err != nil && !errNotExist(err) {
		return fmt.Errorf("localstate: clear recovery quarantine: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("localstate: clear quarantine parent fsync: %w", err)
	}
	return nil
}