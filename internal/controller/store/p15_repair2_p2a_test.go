package store_test

// P15 repair cycle-2 RED P2-A: force node deletion must write the durable
// operation (intent) BEFORE the tombstone/outbox side effects. The pre-fix
// handler called ForceDeleteNode first and CreateNodeDeletionOperation second;
// a storage failure between them left a tombstone/outbox with no pollable
// operation — an orphan terminal fact. This test pins the reordered store/
// lifecycle contract at the exact seam the handler now relies on: with the
// intent already durable, a failing side effect leaves the operation pollable
// and correlated, never an orphan tombstone.

import (
	"context"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/lifecycle"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair2ForceDeletePhaseJournalPrefixInvariant(t *testing.T) {
	s := openRepairStore(t)
	mustNodeRepair(t, s, "node-p2a")

	// The reordered force-delete sequence: durable operation row first.
	if err := s.CreateNodeDeletionOperation(store.NodeDeletionOperation{
		ID: "p2a-op", NodeID: "node-p2a", Status: "PENDING", Mode: "force",
	}); err != nil {
		t.Fatal(err)
	}
	// Side-effect phase fails (outbox enqueue down).
	if _, err := lifecycle.ForceDeleteNode(context.Background(), s,
		lifecycle.DecommissionRequest{NodeID: "node-p2a", OperationID: "p2a-op", Force: true},
		func(store.ControlOutboxItem) error { return errors.New("outbox enqueue down") },
		nil,
	); err == nil {
		t.Fatal("failing outbox side effect must surface an error")
	}

	// Invariant: no tombstone/outbox without a pollable operation.
	if _, err := s.GetNodeDeletionOperation("p2a-op"); err != nil {
		t.Fatalf("durable operation must remain pollable after failed side effect: %v", err)
	}
	ts, err := s.NodeCleanupTombstone("node-p2a")
	if err != nil || ts.OperationID != "p2a-op" {
		t.Fatalf("tombstone = %+v err %v, want operation %q correlated", ts, err, "p2a-op")
	}
	if n, err := s.ControlOutboxCount("node-p2a"); err != nil || n != 0 {
		t.Fatalf("outbox count after failed enqueue = %d err %v, want 0", n, err)
	}
}

func TestP15Repair2DeleteNodeDeletionOperation(t *testing.T) {
	s := openRepairStore(t)
	mustNodeRepair(t, s, "node-p2a-del")
	if err := s.CreateNodeDeletionOperation(store.NodeDeletionOperation{
		ID: "stale-op", NodeID: "node-p2a-del", Status: "PENDING", Mode: "force",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNodeDeletionOperation("stale-op"); err != nil {
		t.Fatalf("delete stale operation = %v", err)
	}
	if _, err := s.GetNodeDeletionOperation("stale-op"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetNodeDeletionOperation after delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteNodeDeletionOperation("stale-op"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
}
