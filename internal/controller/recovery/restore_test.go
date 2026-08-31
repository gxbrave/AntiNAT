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
