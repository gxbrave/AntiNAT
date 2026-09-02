package store_test

// P15 repair cycle-1 RED H3 store tests: the node-deletion watcher needs a
// durable completion surface. The pre-fix code had no way to advance a node
// deletion operation from a node_decommission_ack, so force/normal operations
// stayed PENDING forever.

import (
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// Force mode: completing the ack advances the operation and confirms the
// terminal cleanup tombstone; replay is idempotent.
func TestP15Repair1H3CompleteNodeDeletionResult(t *testing.T) {
	s := openRepairStore(t)
	mustNodeRepair(t, s, "node-del")
	owner, err := s.AcquireControlOwner("node-del", 0, "sess-del-1")
	if err != nil {
		t.Fatal(err)
	}

	op := store.NodeDeletionOperation{ID: "nodedel-1", NodeID: "node-del", Status: "PENDING", Mode: "force"}
	if err := s.CreateNodeDeletionOperation(op); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{NodeID: "node-del", OperationID: "nodedel-1", Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordControlInboxOwned(owner, store.ControlInboxItem{
		MessageID: "ack-del-1", NodeID: "node-del", MessageType: "node_decommission_ack",
		OperationID:     "nodedel-1",
		SemanticPayload: `{"node_id":"node-del","decommission_operation_id":"nodedel-1","status":"DECOMMISSIONED","force":true}`,
	}); err != nil {
		t.Fatal(err)
	}

	results, err := s.ListNodeDeletionResults(10)
	if err != nil || len(results) != 1 || results[0].MessageID != "ack-del-1" {
		t.Fatalf("ListNodeDeletionResults = %+v err %v, want one correlated ack", results, err)
	}

	completed, applied, err := s.CompleteNodeDeletionResult("ack-del-1")
	if err != nil || !applied {
		t.Fatalf("CompleteNodeDeletionResult = ok %v applied %v err %v", completed, applied, err)
	}
	if completed.Status != "COMPLETED" {
		t.Fatalf("operation status = %q, want COMPLETED", completed.Status)
	}
	if got, _ := s.GetNodeDeletionOperation("nodedel-1"); got.Status != "COMPLETED" {
		t.Fatalf("stored operation status = %q, want COMPLETED", got.Status)
	}
	ts, err := s.NodeCleanupTombstone("node-del")
	if err != nil || !ts.RemoteCleanupConfirmed {
		t.Fatalf("cleanup tombstone confirmed = %+v err %v, want confirmed", ts, err)
	}

	// Idempotent replay of the same result.
	if _, applied, err := s.CompleteNodeDeletionResult("ack-del-1"); err != nil || !applied {
		t.Fatalf("replayed CompleteNodeDeletionResult applied %v err %v, want true/nil", applied, err)
	}
}

// Normal mode: a non-force deletion operation completes without synthesizing a
// cleanup tombstone.
func TestP15Repair1H3CompleteNodeDeletionResultNormal(t *testing.T) {
	s := openRepairStore(t)
	mustNodeRepair(t, s, "node-norm")
	owner, err := s.AcquireControlOwner("node-norm", 0, "sess-norm-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNodeDeletionOperation(store.NodeDeletionOperation{ID: "nodedel-norm", NodeID: "node-norm", Status: "PENDING", Mode: "normal"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordControlInboxOwned(owner, store.ControlInboxItem{
		MessageID: "ack-norm-1", NodeID: "node-norm", MessageType: "node_decommission_ack",
		OperationID:     "nodedel-norm",
		SemanticPayload: `{"node_id":"node-norm","decommission_operation_id":"nodedel-norm","status":"DECOMMISSIONED"}`,
	}); err != nil {
		t.Fatal(err)
	}
	completed, applied, err := s.CompleteNodeDeletionResult("ack-norm-1")
	if err != nil || !applied || completed.Status != "COMPLETED" {
		t.Fatalf("complete normal = %+v applied %v err %v", completed, applied, err)
	}
	if _, err := s.NodeCleanupTombstone("node-norm"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("normal node tombstone = %v, want ErrNotFound", err)
	}
}
