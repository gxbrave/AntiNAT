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
	if err := s.ReauthorizeNode("node-q"); err != nil {
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
