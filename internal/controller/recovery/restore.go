// Package recovery owns the P14 controller-side restore/recovery
// reconciliation (v0.8 §7.4): manifest verification, key-mismatch and
// rotation-barrier refusal, staging + atomic switch, and entering
// RESTORE_RECONCILIATION with web-session/enroll-token invalidation and node
// quarantine. Restore never auto-dispatches desired/delete/rotation: nodes
// are quarantined until an administrator reauthorizes them.
package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/lifecycle"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RestoreResult is the durable outcome of a restore.
type RestoreResult struct {
	OperationID   string `json:"restore_operation_id"`
	Phase         string `json:"phase"`
	ForwardCount  int    `json:"forwards"`
	NodesRevision int64  `json:"nodes_revision"`
}

// ErrRestoreRefused is the fail-closed restore refusal.
var ErrRestoreRefused = errors.New("recovery: restore refused")

// ValidateRestore verifies a backup directory (manifest hashes/ACL, SQLite
// quick_check + foreign_key_check), compares the recorded key-id set against
// the live controller keys (key mismatch fails closed), and enforces the
// rotation x backup barrier. It requires the live store only for reads.
func ValidateRestore(ctx context.Context, live *store.Store, backupDir string, liveKeyIDs []string) (store.BackupManifest, error) {
	bs, manifest, err := store.OpenBackup(backupDir)
	if err != nil {
		return store.BackupManifest{}, err
	}
	defer bs.Close()
	if len(manifest.KeyIDs) == 0 {
		return store.BackupManifest{}, fmt.Errorf("%w: backup manifest has no key-id set (older backup format)", ErrRestoreRefused)
	}
	if !sameStringSet(manifest.KeyIDs, liveKeyIDs) {
		return store.BackupManifest{}, fmt.Errorf("%w: key mismatch: backup keys %v vs live keys %v (anti-rollback)", ErrRestoreRefused, manifest.KeyIDs, liveKeyIDs)
	}
	if err := lifecycle.RotationXBackupBarrier(ctx, live); err != nil {
		return store.BackupManifest{}, fmt.Errorf("%w: rotation barrier: %v", ErrRestoreRefused, err)
	}
	if reconciling, err := live.IsRestoreReconciling(); err != nil {
		return store.BackupManifest{}, err
	} else if reconciling {
		return store.BackupManifest{}, fmt.Errorf("%w: controller is already reconciling a restore", ErrRestoreRefused)
	}
	return manifest, nil
}

// ApplyRestore stages the backup database into the live directory, verifies it
// under the frozen integrity checks, atomically switches it over the live
// database file, then enters RESTORE_RECONCILIATION on the restored store. The
// caller must have quiesced (closed) the live store on liveDBPath first.
func ApplyRestore(ctx context.Context, liveDBPath, backupDir string) (store.RestoreOperation, error) {
	if liveDBPath == "" || backupDir == "" {
		return store.RestoreOperation{}, fmt.Errorf("%w: paths required", ErrRestoreRefused)
	}
	backupDB := filepath.Join(backupDir, "controller.db")
	src, err := os.ReadFile(backupDB)
	if err != nil {
		return store.RestoreOperation{}, err
	}
	dir := filepath.Dir(liveDBPath)
	stagePath := filepath.Join(dir, "controller.db.stage")
	if err := os.WriteFile(stagePath, src, 0o600); err != nil {
		return store.RestoreOperation{}, fmt.Errorf("recovery: stage restore: %w", err)
	}
	if err := syncFileAndParent(stagePath); err != nil {
		return store.RestoreOperation{}, err
	}
	// Verify the staged copy with the same frozen integrity checks the store
	// applies on Open.
	staged, err := store.Open(stagePath)
	if err != nil {
		_ = os.Remove(stagePath)
		return store.RestoreOperation{}, fmt.Errorf("%w: staged database failed integrity: %v", ErrRestoreRefused, err)
	}
	if err := staged.Close(); err != nil {
		_ = os.Remove(stagePath)
		return store.RestoreOperation{}, err
	}
	if err := os.Rename(stagePath, liveDBPath); err != nil {
		_ = os.Remove(stagePath)
		return store.RestoreOperation{}, fmt.Errorf("recovery: atomic switch restore: %w", err)
	}
	if err := syncFileAndParent(liveDBPath); err != nil {
		return store.RestoreOperation{}, err
	}
	// Open the restored database and enter RESTORE_RECONCILIATION.
	restored, err := store.Open(liveDBPath)
	if err != nil {
		return store.RestoreOperation{}, err
	}
	op := store.RestoreOperation{
		ID:             randomHex16(),
		ManifestSHA256: manifestSHA256(backupDir),
		SchemaVersion:  1,
		Phase:          "RESTORE_RECONCILIATION",
	}
	if err := restored.EnterRestoreReconciliation(op); err != nil {
		restored.Close()
		return store.RestoreOperation{}, err
	}
	return op, nil
}

// EnterRestoreReconciliationOn wraps the durable reconciliation entry for an
// already-open restored store (used by callers that switch the file
// themselves).
func EnterRestoreReconciliationOn(restored *store.Store, op store.RestoreOperation) error {
	return restored.EnterRestoreReconciliation(op)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(b))
	for _, v := range b {
		seen[v]++
	}
	for _, v := range a {
		if seen[v] == 0 {
			return false
		}
		seen[v]--
	}
	return true
}

func manifestSHA256(backupDir string) string {
	src, err := os.ReadFile(filepath.Join(backupDir, "manifest.json"))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(src)
	return hex.EncodeToString(sum[:])
}

func randomHex16() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("restore-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func syncFileAndParent(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("recovery: open for sync: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	return err
}
