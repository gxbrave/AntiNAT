// P14 Story 5: backup/restore anti-rollback.
//
// RED reasons captured:
//   - ValidateRestore / ApplyRestore do not exist -> cannot compile -> RED.
//   - The terminal facts the spec demands (backup after delete then restore
//     old state must NOT auto-dispatch, key mismatch refused, bit flip refused,
//     concurrent rotation refused) have no implementation.
package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/lifecycle"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// TestRestoreAfterDeleteEntersReconciliationWithoutResurrection is the story's
// core RED: backup after a deletion, then restore the old state. The restored
// controller enters RESTORE_RECONCILIATION with every node quarantined and
// refuses every automatic desired/delete/rotation dispatch, so the deleted
// Forward is never resurrected by an old snapshot.
func TestRestoreAfterDeleteEntersReconciliationWithoutResurrection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")

	// Phase 1: a live controller with a node + a Forward, then a deletion op.
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.CreateNode(store.Node{ID: "node-1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.CreateForward(store.Forward{ID: "fwd-a", NodeID: "node-1", Name: "fa", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.CreateForward(store.Forward{ID: "fwd-b", NodeID: "node-1", Name: "fb", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	// A durable forward deletion operation (the delete fact).
	if err := live.ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: "del-op-1", ForwardID: "fwd-a", Status: "PENDING", DesiredRevision: 0,
	}, store.ControlOutboxItem{OperationID: "del-op-1", MessageType: "forward_delete", NodeID: "node-1", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	// The delete fact must NOT remove the forward row yet (desired ABSENT is
	// delivered to the agent; the row is tombstoned on ACK).
	if _, err := live.GetForward("fwd-a"); err != nil {
		t.Fatalf("forward deleted before ABSENT applied: %v", err)
	}

	keys := []string{"live-key-1"}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, keys); err != nil {
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}

	// Phase 2: restore the old state. After ApplyRestore the controller must be
	// in RESTORE_RECONCILIATION and refuse auto-dispatch.
	op, err := ApplyRestore(ctx, livePath, backupDir)
	if err != nil {
		t.Fatalf("apply restore: %v", err)
	}
	if op.Phase != "RESTORE_RECONCILIATION" {
		t.Fatalf("restore op phase = %q", op.Phase)
	}
	restored, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	reconciling, err := restored.IsRestoreReconciling()
	if err != nil || !reconciling {
		t.Fatalf("IsRestoreReconciling = %v err=%v", reconciling, err)
	}
	quarantined, err := restored.IsNodeQuarantined("node-1")
	if err != nil || !quarantined {
		t.Fatalf("node quarantined = %v err=%v", quarantined, err)
	}
	// Automatic dispatch of the deleted forward's old desired is refused.
	if err := restored.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "re-desir", MessageType: "desired", NodeID: "node-1", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("desired accepted during RESTORE_RECONCILIATION (old snapshot could resurrect the deletion)")
	}
	if err := restored.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "re-del", MessageType: "forward_delete", NodeID: "node-1", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("forward_delete accepted during RESTORE_RECONCILIATION")
	}
	// The deletion + quarantine facts survive: the deleted forward is NOT
	// resurrected by the restart because no dispatch is automatic.
	if _, err := restored.GetForward("fwd-b"); err != nil {
		t.Fatalf("restored forward fwd-b: %v", err)
	}
}

// TestRestoreOldBackupDoesNotResurrectDeletedForward is the anti-rollback core:
// backup BEFORE a deletion, delete, then restore the pre-delete snapshot. The
// old snapshot contains the Forward, but the restored controller enters
// RESTORE_RECONCILIATION with the node quarantined — no PRESENT desired is
// auto-dispatched — and the Agent's durable tombstone is never overridden by
// an old snapshot. Resurrecting a deleted Forward therefore requires explicit
// operator reauthorization + reconciliation, never automatic dispatch.
func TestRestoreOldBackupDoesNotResurrectDeletedForward(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.CreateNode(store.Node{ID: "node-1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.CreateForward(store.Forward{ID: "fwd-a", NodeID: "node-1", Name: "fa", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	preDeleteBackup := filepath.Join(dir, "pre-delete-backup")
	if _, err := live.BackupToWithKeys(preDeleteBackup, []string{"live-key-1"}); err != nil {
		t.Fatal(err)
	}
	// After the above backup the operator deletes fwd-a.
	if err := live.ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: "del-op-2", ForwardID: "fwd-a", Status: "PENDING", DesiredRevision: 0,
	}, store.ControlOutboxItem{OperationID: "del-op-2", MessageType: "forward_delete", NodeID: "node-1", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	// Restore the PRE-delete snapshot.
	if _, err := ApplyRestore(ctx, livePath, preDeleteBackup); err != nil {
		t.Fatalf("apply restore: %v", err)
	}
	restored, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err := restored.GetForward("fwd-a"); err != nil {
		t.Fatalf("old snapshot forward missing: %v", err)
	}
	reconciling, err := restored.IsRestoreReconciling()
	if err != nil || !reconciling {
		t.Fatalf("IsRestoreReconciling = %v err=%v", reconciling, err)
	}
	// PRESENT desired must NOT be auto-dispatched: the delete happened after
	// this snapshot, so delivering it would resurrect the forwarded service.
	if err := restored.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "pres-desir", MessageType: "desired", NodeID: "node-1", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("PRESENT desired auto-dispatched during RECONCILIATION (resurrection risk)")
	}
	if err := restored.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "node-decom-x", MessageType: "node_decommission", NodeID: "node-1", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatalf("cleanup-authorized enqueue refused: %v", err)
	}
}

// TestRestoreKeyMismatchRefused: a backup signed under different controller
// keys is refused fail-closed.
func TestRestoreKeyMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRestore(context.Background(), live, backupDir, []string{"key-B"}); err == nil {
		t.Fatal("restore with mismatched keys accepted")
	}
	live.Close()
}

// TestRestoreBitFlipRefused: a flipped byte in the backup database breaks the
// manifest hash, so OpenBackup fails before anything is touched.
func TestRestoreBitFlipRefused(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	live.Close()
	db := filepath.Join(backupDir, "controller.db")
	data, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xFF
	if err := os.WriteFile(db, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenBackup(backupDir); err == nil {
		t.Fatal("bit-flipped backup passed verification")
	}
}

// TestRestoreRotationBarrierRefused: an in-flight key rotation blocks restore.
func TestRestoreRotationBarrierRefused(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	// Prepare a rotation (leaves a non-terminal key_rotation_operations row).
	keyDir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(keyDir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := int64(1700000000)
	if _, err := lifecycle.PrepareRotation(context.Background(), live, keyDir, oldKey, "controller", "rot-x", now, now+3600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRestore(context.Background(), live, backupDir, []string{"key-A"}); err == nil {
		t.Fatal("restore accepted during an in-flight rotation")
	}
}

// TestRestoreMissingKeyIDsRefused: an old-format backup without a key-id set is
// refused (no guessing).
func TestRestoreMissingKeyIDsRefused(t *testing.T) {
	dir := t.TempDir()
	live, err := store.Open(filepath.Join(dir, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	backupDir := filepath.Join(dir, "backup")
	// BackupTo (no keys) still records empty KeyIDs; a legacy manifest without
	// the field decodes as empty and must be refused.
	if _, err := live.BackupTo(backupDir); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRestore(context.Background(), live, backupDir, []string{"key-A"}); err == nil {
		t.Fatal("backup without key-id set accepted for restore")
	}
}

// TestRestoreReauthorizeNodeClearsQuarantine drives the manual administrator
// reauthorization boundary.
func TestRestoreReauthorizeNodeClearsQuarantine(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifeCreateNode(t, live); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRestore(context.Background(), livePath, backupDir); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.ReauthorizeNode("node-1"); err != nil {
		t.Fatal(err)
	}
	q, err := restored.IsNodeQuarantined("node-1")
	if err != nil || q {
		t.Fatalf("node still quarantined after reauthorization: %v %v", q, err)
	}
}

func lifeCreateNode(t *testing.T, s *store.Store) error {
	return s.CreateNode(store.Node{ID: "node-1", Name: "n1"})
}

// TestRestoreCrashMidSwitchLeavesReconciling (repair-1 M6a): the
// RESTORE_RECONCILIATION intent is durable INSIDE the staged DB before the
// atomic rename. A crash at any point before the switch leaves the OLD live DB
// untouched; a crash after the switch leaves the NEW live DB that ALREADY
// carries the quarantine row. In neither case can the controller come up on a
// switched-in restored DB and silently resume automatic dispatch.
func TestRestoreCrashMidSwitchLeavesReconciling(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.CreateNode(store.Node{ID: "node-1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.CreateForward(store.Forward{ID: "fwd-a", NodeID: "node-1", Name: "fa", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}

	// Crash BEFORE the switch: the staged file already carries the durable intent.
	stagePath, op, err := prepareRestoreStage(livePath, backupDir)
	if err != nil {
		t.Fatalf("prepare stage: %v", err)
	}
	stage, err := store.Open(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	reconciling, err := stage.IsRestoreReconciling()
	if err != nil || !reconciling {
		t.Fatalf("staged DB IsRestoreReconciling = %v err=%v (intent not durable before switch)", reconciling, err)
	}
	if err := stage.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "crash-desire", MessageType: "desired", NodeID: "node-1", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("staged DB accepted desired before the switch (intent not durable)")
	}
	stage.Close()
	_ = op
	// The OLD live DB is untouched by the crash-before-switch: still openable,
	// but the stage that was prepared carries the intent.

	// Crash AFTER the switch (rename committed): the new live DB is reconciling.
	if err := commitRestore(livePath, stagePath); err != nil {
		t.Fatalf("commit restore: %v", err)
	}
	restored, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	reconciling, err = restored.IsRestoreReconciling()
	if err != nil || !reconciling {
		t.Fatalf("restored live IsRestoreReconciling = %v err=%v after switch", reconciling, err)
	}
	if err := restored.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "crash-desire-2", MessageType: "desired", NodeID: "node-1", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("restored live accepted desired after switch (never silent dispatch)")
	}
	// Entering the SAME operation again is idempotent (crash-retry safety).
	if err := restored.EnterRestoreReconciliation(op); err != nil {
		t.Fatalf("idempotent re-enter: %v", err)
	}
	if reconciling, _ := restored.IsRestoreReconciling(); !reconciling {
		t.Fatal("re-entering the same operation left the controller un-reconciled")
	}
}

// TestRestoreHighWaterIntegrityRefused (repair-1 M6b semantic-integrity): the
// manifest HighWater must match the backup DB's ACTUAL contents. A tampered
// backup whose rows were removed AND whose per-file hash was recomputed passes
// OpenBackup but is refused by ValidateRestore on the high-water mismatch.
func TestRestoreHighWaterIntegrityRefused(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifeCreateNode(t, live); err != nil {
		t.Fatal(err)
	}
	if _, err := live.CreateForward(store.Forward{ID: "fwd-a", NodeID: "node-1", Name: "fa", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	// Tamper: delete the forward row directly in the backup DB.
	tampered, err := store.Open(filepath.Join(backupDir, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tampered.DeleteForwardRow("fwd-a"); err != nil {
		t.Fatal(err)
	}
	if err := tampered.Close(); err != nil {
		t.Fatal(err)
	}
	// Recompute the per-file SHA so OpenBackup (hash check) passes; the manifest
	// HighWater is deliberately left stale (forwards=1 while the DB has 0).
	recomputeManifestHash(t, backupDir, "controller.db")

	if _, err := ValidateRestore(context.Background(), live, backupDir, []string{"key-A"}); err == nil {
		t.Fatal("tampered backup (manifest high-water vs DB contents) passed ValidateRestore")
	}
	live.Close()
}

// TestRestoreHighWaterRollbackRefused (repair-1 M6b anti-rollback): a
// PRE-deletion backup restored onto a live store that has since accumulated the
// deletion fact is refused by ValidateRestore — restoring it would drop the
// operator's deletion.
func TestRestoreHighWaterRollbackRefused(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "controller.db")
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifeCreateNode(t, live); err != nil {
		t.Fatal(err)
	}
	if _, err := live.CreateForward(store.Forward{ID: "fwd-a", NodeID: "node-1", Name: "fa", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	// Backup BEFORE the deletion.
	backupDir := filepath.Join(dir, "pre-delete-backup")
	if _, err := live.BackupToWithKeys(backupDir, []string{"key-A"}); err != nil {
		t.Fatal(err)
	}
	// The operator deletes after the backup.
	if err := live.ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: "del-rollback", ForwardID: "fwd-a", Status: "PENDING", DesiredRevision: 0,
	}, store.ControlOutboxItem{OperationID: "del-rollback", MessageType: "forward_delete", NodeID: "node-1", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	// ValidateRestore must refuse the pre-deletion backup (live has more
	// deletion facts than the backup manifest records).
	if _, err := ValidateRestore(context.Background(), live, backupDir, []string{"key-A"}); err == nil {
		t.Fatal("pre-deletion backup accepted by ValidateRestore against a live store with the deletion")
	}
	live.Close()
}

// recomputeManifestHash rewrites manifest.json with a fresh SHA256 for the named
// backup file so OpenBackup's hash check passes after a deliberate DB mutation.
func recomputeManifestHash(t *testing.T, backupDir, dbName string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(backupDir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	manPath := filepath.Join(backupDir, "manifest.json")
	data, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		Schema string `json:"schema"`
		Files  []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
			Mode   uint32 `json:"mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &man); err != nil {
		t.Fatal(err)
	}
	for i := range man.Files {
		if man.Files[i].Name == dbName {
			man.Files[i].SHA256 = hex.EncodeToString(sum[:])
		}
	}
	out, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
