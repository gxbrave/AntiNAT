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
	// repair-1 M6b: the manifest HighWater recorded at backup is now COMPARED.
	// First the semantic-integrity check: the manifest's high-water must equal
	// the actual contents of the backup DB. A tampered backup (rows removed or
	// recreated, with the per-file hash recomputed to match) is rejected even
	// though OpenBackup's hash check passes. Second the anti-rollback check
	// against the LIVE store: restoring a backup whose deletion/tombstone/
	// node-revision high-water is BELOW the live store's current values would
	// silently DROP facts the operator has already made (a pre-deletion backup),
	// so it is refused here — the dispatch-level quarantine is what rejects any
	// row that would resurrect a deletion "via any window".
	backupHW, err := bs.CurrentBackupHighWater()
	if err != nil {
		return store.BackupManifest{}, fmt.Errorf("%w: backup high-water: %v", ErrRestoreRefused, err)
	}
	m := manifest.HighWater
	if m.Forwards != backupHW.Forwards || m.ForwardSpecs != backupHW.ForwardSpecs ||
		m.Deletions != backupHW.Deletions || m.CleanupTombstones != backupHW.CleanupTombstones ||
		m.NodesRevision != backupHW.NodesRevision {
		return store.BackupManifest{}, fmt.Errorf("%w: high-water mismatch: manifest %+v vs backup database contents %+v", ErrRestoreRefused, m, backupHW)
	}
	liveHW, err := live.CurrentBackupHighWater()
	if err != nil {
		return store.BackupManifest{}, fmt.Errorf("%w: live high-water: %v", ErrRestoreRefused, err)
	}
	if m.Deletions < liveHW.Deletions || m.CleanupTombstones < liveHW.CleanupTombstones ||
		m.NodesRevision < liveHW.NodesRevision {
		return store.BackupManifest{}, fmt.Errorf("%w: backup high-water is older than the live store (deletions %d<%d, tombstones %d<%d, node revision %d<%d) — restoring would drop operator facts", ErrRestoreRefused,
			m.Deletions, liveHW.Deletions, m.CleanupTombstones, liveHW.CleanupTombstones, m.NodesRevision, liveHW.NodesRevision)
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

// maxRestoreDBBytes bounds the in-memory backup DB read (repair-1 L7): the
// restore path reads the whole controller.db into memory before staging it, so
// an oversized backup must fail closed rather than exhaust the controller.
// The single source of truth is store.MaxBackupFileBytes (repair-2 L-A also
// applies it to the manifest sibling-file verification in store.hashAndMode).
const maxRestoreDBBytes = store.MaxBackupFileBytes

// ApplyRestore is the validated restore orchestration. The live store and the
// live controller key-id set are mandatory context; the function validates the
// backup (including manifest hashes, key identity, high-water anti-rollback,
// and rotation/reconciliation barriers) before closing the live store and
// switching the prepared database. The raw stage/switch helpers are private.
func ApplyRestore(ctx context.Context, live *store.Store, liveDBPath, backupDir string, liveKeyIDs []string) (store.RestoreOperation, error) {
	if live == nil || len(liveKeyIDs) == 0 {
		return store.RestoreOperation{}, fmt.Errorf("%w: live store and key context are required", ErrRestoreRefused)
	}
	if _, err := ValidateRestore(ctx, live, backupDir, liveKeyIDs); err != nil {
		return store.RestoreOperation{}, err
	}
	if err := live.Close(); err != nil {
		return store.RestoreOperation{}, fmt.Errorf("%w: close live store before switch: %v", ErrRestoreRefused, err)
	}
	stagePath, op, err := prepareRestoreStage(liveDBPath, backupDir)
	if err != nil {
		return store.RestoreOperation{}, err
	}
	if err := commitRestore(liveDBPath, stagePath); err != nil {
		_ = os.Remove(stagePath)
		return store.RestoreOperation{}, err
	}
	return op, nil
}

// prepareRestoreStage copies the backup DB to the live dir, verifies integrity,
// and writes the RESTORE_RECONCILIATION intent into the staged copy. It returns
// the staged path and the durable op WITHOUT switching anything. This is the
// durable-PREPARE phase of the restore switch (repair-1 M6a/L7).
func prepareRestoreStage(liveDBPath, backupDir string) (string, store.RestoreOperation, error) {
	if liveDBPath == "" || backupDir == "" {
		return "", store.RestoreOperation{}, fmt.Errorf("%w: paths required", ErrRestoreRefused)
	}
	backupDB := filepath.Join(backupDir, "controller.db")
	// repair-1 L7: bound the in-memory read.
	st, err := os.Stat(backupDB)
	if err != nil {
		return "", store.RestoreOperation{}, err
	}
	if st.Size() > maxRestoreDBBytes {
		return "", store.RestoreOperation{}, fmt.Errorf("%w: backup database %d bytes exceeds the %d byte restore bound", ErrRestoreRefused, st.Size(), maxRestoreDBBytes)
	}
	src, err := os.ReadFile(backupDB)
	if err != nil {
		return "", store.RestoreOperation{}, err
	}
	dir := filepath.Dir(liveDBPath)
	stagePath := filepath.Join(dir, "controller.db.stage")
	if err := os.WriteFile(stagePath, src, 0o600); err != nil {
		return "", store.RestoreOperation{}, fmt.Errorf("recovery: stage restore: %w", err)
	}
	if err := syncFileAndParent(stagePath); err != nil {
		return "", store.RestoreOperation{}, err
	}
	// Verify the staged copy with the same frozen integrity checks the store
	// applies on Open, then WRITE the reconciliation intent into it. Entering
	// RESTORE_RECONCILIATION on the STAGED copy (repair-1 M6a) makes the intent
	// durable inside the exact file that will become live, so there is no window
	// where a live switched-in DB lacks the quarantine row.
	staged, err := store.Open(stagePath)
	if err != nil {
		_ = os.Remove(stagePath)
		return "", store.RestoreOperation{}, fmt.Errorf("%w: staged database failed integrity: %v", ErrRestoreRefused, err)
	}
	op := store.RestoreOperation{
		ID:             randomHex16(),
		ManifestSHA256: manifestSHA256(backupDir),
		SchemaVersion:  1,
		Phase:          "RESTORE_RECONCILIATION",
	}
	if err := staged.EnterRestoreReconciliation(op); err != nil {
		staged.Close()
		_ = os.Remove(stagePath)
		return "", store.RestoreOperation{}, err
	}
	if err := staged.Close(); err != nil {
		_ = os.Remove(stagePath)
		return "", store.RestoreOperation{}, err
	}
	// The SQLite close checkpoints the WAL into the main file; fsync it so the
	// durable intent survives the crash window up to the rename.
	if err := syncFileAndParent(stagePath); err != nil {
		_ = os.Remove(stagePath)
		return "", store.RestoreOperation{}, err
	}
	return stagePath, op, nil
}

// commitRestore atomically switches the prepared staged DB over the live path
// and fsyncs the parent directory.
func commitRestore(liveDBPath, stagePath string) error {
	if err := os.Rename(stagePath, liveDBPath); err != nil {
		return fmt.Errorf("recovery: atomic switch restore: %w", err)
	}
	if err := syncFileAndParent(liveDBPath); err != nil {
		return err
	}
	return nil
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
