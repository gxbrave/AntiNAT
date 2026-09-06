// P14 repair-1 H2/M3 store-level tests: the cleanup-only/restore-quarantine
// enqueue guard is enforced inside the direct control_outbox insert paths (M3b),
// and DispatchAllowed + the reauthorize/finalize flow gate per-node quarantine
// (H2).
package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// TestCleanupTombstoneDuplicateRefused (repair-1 L2): a second tombstone for an
// already-tombstoned node with a DIFFERENT operation id is refused and the
// terminal fact keeps the FIRST operation id; an idempotent retry of the SAME
// operation succeeds and refreshes the timestamp.
func TestCleanupTombstoneDuplicateRefused(t *testing.T) {
	s, _, _ := openTest(t)
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-1", OperationID: "tomb-first", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	// A different operation id must be refused (the terminal fact never forks).
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-1", OperationID: "tomb-second", Force: true,
	}); err == nil {
		t.Fatal("second cleanup tombstone with a different operation id was accepted")
	}
	ts, err := s.NodeCleanupTombstone("node-1")
	if err != nil {
		t.Fatal(err)
	}
	if ts.OperationID != "tomb-first" {
		t.Fatalf("terminal fact operation id = %q, want tomb-first (silently kept?)", ts.OperationID)
	}
	// Idempotent retry of the SAME operation succeeds.
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-1", OperationID: "tomb-first", Force: true,
	}); err != nil {
		t.Fatalf("idempotent retry of the same operation refused: %v", err)
	}
}

// TestCreateForwardBundleRefusedAfterCleanupTombstone (repair-1 M3b): the
// forward-bundle transaction inserts its desired control_outbox row directly
// (bypassing EnqueueControlOutbox). Once a cleanup tombstone exists, creating a
// forward for that node must be refused and roll back every side effect.
func TestCreateForwardBundleRefusedAfterCleanupTombstone(t *testing.T) {
	s, _, _ := openTest(t)
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-1", OperationID: "tomb-op-1", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	f, spec, outbox, idem := atomicForwardFixture(t, s, "bundle-op-tomb")
	_, _, err := s.CreateForwardBundle(context.Background(), f, spec, outbox, idem)
	if err == nil {
		t.Fatal("CreateForwardBundle succeeded for a cleanup-only (force-deleted) node")
	}
	if got, err := s.ForwardCount(); err != nil || got != 1 {
		t.Fatalf("ForwardCount = %d (err %v), forward bundle side effect survived refusal", got, err)
	}
	if got, err := s.ControlOutboxCount("node-1"); err != nil || got != 0 {
		t.Fatalf("ControlOutboxCount = %d (err %v), desired outbox row survived refusal", got, err)
	}
	if _, err := s.GetIdempotency(idem.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("idempotency row survived refused bundle: %v", err)
	}
}

// TestDeliveryAllowedGatesPerNodeQuarantineAndRestoreReconciliation (repair-1
// H2b): a forbidden orchestrating message is refused while the controller is in
// RESTORE_RECONCILIATION, while the node is per-node quarantined, and while a
// cleanup tombstone exists; it becomes allowed only after the global finalize
// AND the per-node reauthorization. Non-forbidden types stay allowed throughout.
func TestDeliveryAllowedGatesPerNodeQuarantineAndRestoreReconciliation(t *testing.T) {
	s, _, _ := openTest(t)

	node2 := store.Node{ID: "node-q", Name: "nq"}
	if err := s.CreateNode(node2); err != nil {
		t.Fatal(err)
	}

	if allowed, err := s.DeliveryAllowed("node-q", "desired"); err != nil || !allowed {
		t.Fatalf("DeliveryAllowed(desired) before any quarantine = %v err=%v", allowed, err)
	}

	// RESTORE_RECONCILIATION suspends ALL nodes.
	if err := s.EnterRestoreReconciliation(store.RestoreOperation{
		ID: "rest-op-global", ControllerInstance: "ci-1",
		ManifestSHA256: "deadbeef", SchemaVersion: 1, Phase: "RESTORE_RECONCILIATION",
	}); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.DeliveryAllowed("node-q", "desired"); allowed {
		t.Fatal("DeliveryAllowed(desired) true during RESTORE_RECONCILIATION")
	}
	// node_decommission (cleanup-authorized) still flows.
	if allowed, _ := s.DeliveryAllowed("node-q", "node_decommission"); !allowed {
		t.Fatal("DeliveryAllowed(node_decommission) false during reconciliation")
	}

	// Per-node global finalize alone does NOT resume dispatch.
	if err := s.AdvanceRestorePhase("rest-op-global", "AUTHORIZED"); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.DeliveryAllowed("node-q", "desired"); allowed {
		t.Fatal("DeliveryAllowed(desired) true after finalize but before node reauthorization (per-node quarantine still set)")
	}

	// Per-node reauthorization + global finalize resumes dispatch.
	if err := s.ReauthorizeNodeForOperation("node-q", "rest-op-global"); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.DeliveryAllowed("node-q", "desired"); err != nil || !allowed {
		t.Fatalf("DeliveryAllowed(desired) after finalize+reauthorize = %v err=%v", allowed, err)
	}

	// A cleanup tombstone re-gates the same node.
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-q", OperationID: "tomb-op-q", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.DeliveryAllowed("node-q", "desired"); allowed {
		t.Fatal("DeliveryAllowed(desired) true after cleanup tombstone")
	}
}

// TestForceRetireKeyRotationOperationAtomic (repair-1 L1): the force-retire
// fast-forward lands on RETIRED in ONE statement. Seeding an ACKED operation and
// calling the atomic store method must produce RETIRED (never a transient ACTIVE
// that a crash could leave behind while the operation claims RETIRED), and the
// FSM guard is preserved: a PREPARED operation is refused.
func TestForceRetireKeyRotationOperationAtomic(t *testing.T) {
	s, _, _ := openTest(t)

	op := store.KeyRotationOperation{
		ID: "rot-atomic", Scope: "controller", OldKeyID: "old", NewKeyID: "new",
		NewGeneration: 2, Phase: "ACKED", NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
	}
	if err := s.CreateKeyRotationOperation(op); err != nil {
		t.Fatal(err)
	}
	if err := s.ForceRetireKeyRotationOperation("rot-atomic"); err != nil {
		t.Fatalf("atomic force retire: %v", err)
	}
	got, err := s.GetKeyRotationOperation("rot-atomic")
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != "RETIRED" {
		t.Fatalf("phase = %q, want RETIRED (single atomic write, no half-updated ACTIVE)", got.Phase)
	}

	// A PREPARED operation is NOT force-retirable (preserves the FSM guard).
	pre := store.KeyRotationOperation{
		ID: "rot-pre", Scope: "controller", OldKeyID: "old", NewKeyID: "new",
		NewGeneration: 2, Phase: "PREPARED", NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
	}
	if err := s.CreateKeyRotationOperation(pre); err != nil {
		t.Fatal(err)
	}
	if err := s.ForceRetireKeyRotationOperation("rot-pre"); err == nil {
		t.Fatal("force retire accepted from PREPARED")
	}
	preGot, err := s.GetKeyRotationOperation("rot-pre")
	if err != nil {
		t.Fatal(err)
	}
	if preGot.Phase != "PREPARED" {
		t.Fatalf("PREPARED operation phase changed to %q after refused force retire", preGot.Phase)
	}
}
