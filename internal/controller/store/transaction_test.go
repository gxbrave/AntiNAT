package store_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// openTest is a shared helper: fresh DB in a temp dir with a node and a
// forward ready for transactional stories.
func openTest(t *testing.T) (*store.Store, store.Node, store.Forward) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	node := store.Node{ID: "node-1", Name: "n1"}
	if err := s.CreateNode(node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	fwd, err := s.CreateForward(store.Forward{
		ID: "fwd-1", NodeID: "node-1", Name: "web", Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("CreateForward: %v", err)
	}
	return s, node, fwd
}

// RED 2a: a desired change, its operation record and the control-outbox entry
// commit atomically; when the outbox insert faults (unique operation/message
// conflict), the desired change and parent revision roll back too.
func TestApplyForwardDesiredRollsBackOnOutboxFault(t *testing.T) {
	s, _, fwd := openTest(t)

	// Pre-arm a conflicting outbox row for the same (operation_id, message_type)
	// so the enqueue step inside the transaction faults.
	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-desired-1", MessageType: "C2A_DESIRED",
		NodeID: "node-1", SemanticPayload: `{"stale":true}`,
	}); err != nil {
		t.Fatalf("pre-arm outbox: %v", err)
	}

	err := s.ApplyForwardDesired(store.ForwardSpec{
		ID: "spec-1", ForwardID: fwd.ID, Revision: 1,
		SpecJSON: `{"name":"web","protocol":"tcp"}`,
	}, store.ControlOutboxItem{
		OperationID: "op-desired-1", MessageType: "C2A_DESIRED",
		NodeID: "node-1", SemanticPayload: `{"desired_revision":1}`,
	})
	if err == nil {
		t.Fatal("ApplyForwardDesired with conflicting outbox succeeded, want fault")
	}

	// All three steps must have rolled back: no spec row, parent revision
	// unchanged, no second outbox row for the operation.
	if count, err := s.ForwardSpecCount(fwd.ID); err != nil || count != 0 {
		t.Fatalf("ForwardSpecCount = %d (err %v), want 0 after rollback", count, err)
	}
	got, err := s.GetForward(fwd.ID)
	if err != nil {
		t.Fatalf("GetForward: %v", err)
	}
	if got.Revision != 0 {
		t.Fatalf("forward revision = %d after rollback, want 0", got.Revision)
	}
	if count, err := s.ControlOutboxCount("node-1"); err != nil || count != 1 {
		t.Fatalf("ControlOutboxCount = %d (err %v), want exactly the pre-armed 1", count, err)
	}
}

// RED 2b: on success the desired spec, parent revision bump and outbox entry
// are all persisted.
func TestApplyForwardDesiredCommitsAll(t *testing.T) {
	s, _, fwd := openTest(t)

	err := s.ApplyForwardDesired(store.ForwardSpec{
		ID: "spec-1", ForwardID: fwd.ID, Revision: 1,
		SpecJSON: `{"name":"web","protocol":"tcp"}`,
	}, store.ControlOutboxItem{
		OperationID: "op-desired-1", MessageType: "C2A_DESIRED",
		NodeID: "node-1", SemanticPayload: `{"desired_revision":1}`,
	})
	if err != nil {
		t.Fatalf("ApplyForwardDesired: %v", err)
	}

	if count, err := s.ForwardSpecCount(fwd.ID); err != nil || count != 1 {
		t.Fatalf("ForwardSpecCount = %d (err %v), want 1", count, err)
	}
	got, err := s.GetForward(fwd.ID)
	if err != nil {
		t.Fatalf("GetForward: %v", err)
	}
	if got.Revision != 1 {
		t.Fatalf("forward revision = %d, want 1", got.Revision)
	}
	if count, err := s.ControlOutboxCount("node-1"); err != nil || count != 1 {
		t.Fatalf("ControlOutboxCount = %d (err %v), want 1", count, err)
	}
}

// RED 2c: a forward delete operation and its outbox command commit atomically;
// a fault in the outbox step rolls back the deletion operation.
func TestApplyForwardDeleteRollsBackOnOutboxFault(t *testing.T) {
	s, _, fwd := openTest(t)

	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "delop-1", MessageType: "C2A_FORWARD_DELETE",
		NodeID: "node-1", SemanticPayload: `{"stale":true}`,
	}); err != nil {
		t.Fatalf("pre-arm outbox: %v", err)
	}

	err := s.ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: "delop-1", ForwardID: fwd.ID, Status: "PENDING", DesiredRevision: fwd.Revision,
	}, store.ControlOutboxItem{
		OperationID: "delop-1", MessageType: "C2A_FORWARD_DELETE",
		NodeID: "node-1", SemanticPayload: `{"forward_id":"fwd-1"}`,
	})
	if err == nil {
		t.Fatal("ApplyForwardDelete with conflicting outbox succeeded, want fault")
	}
	if _, err := s.GetForwardDeletionOperation("delop-1"); err == nil {
		t.Fatal("deletion operation survived a failed transaction")
	}
}

// RED R7-3: delete intent is fenced by the stable parent revision; a stale
// caller cannot enqueue a second delete after another mutation advanced it.
func TestApplyForwardDeleteRejectsStaleParentRevision(t *testing.T) {
	s, _, fwd := openTest(t)
	first := store.ForwardDeletionOperation{ID: "delop-1", ForwardID: fwd.ID, Status: "PENDING", DesiredRevision: fwd.Revision}
	if err := s.ApplyForwardDelete(first, store.ControlOutboxItem{
		OperationID: "delop-1", MessageType: "C2A_FORWARD_DELETE", NodeID: "node-1",
		SemanticPayload: `{"forward_id":"fwd-1"}`,
	}); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	stale := store.ForwardDeletionOperation{ID: "delop-2", ForwardID: fwd.ID, Status: "PENDING", DesiredRevision: fwd.Revision}
	err := s.ApplyForwardDelete(stale, store.ControlOutboxItem{
		OperationID: "delop-2", MessageType: "C2A_FORWARD_DELETE", NodeID: "node-1",
		SemanticPayload: `{"forward_id":"fwd-1","retry":true}`,
	})
	if !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("stale delete error = %v, want ErrCASConflict", err)
	}
	if _, err := s.GetForwardDeletionOperation(stale.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale deletion operation = %v, want absent", err)
	}
}

// RED R7-4: replaying one deletion operation is idempotent and does not try to
// bump the parent revision or insert a duplicate outbox row.
func TestApplyForwardDeleteReplayIsIdempotent(t *testing.T) {
	s, _, fwd := openTest(t)
	op := store.ForwardDeletionOperation{ID: "delop-replay", ForwardID: fwd.ID, Status: "PENDING", DesiredRevision: fwd.Revision}
	outbox := store.ControlOutboxItem{
		OperationID: "delop-replay", MessageType: "C2A_FORWARD_DELETE", NodeID: "node-1",
		SemanticPayload: `{"forward_id":"fwd-1"}`,
	}
	if err := s.ApplyForwardDelete(op, outbox); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := s.ApplyForwardDelete(op, outbox); err != nil {
		t.Fatalf("replayed delete: %v", err)
	}
	got, err := s.GetForward(fwd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != fwd.Revision+1 {
		t.Fatalf("forward revision = %d, want %d", got.Revision, fwd.Revision+1)
	}
	if count, err := s.ControlOutboxCount("node-1"); err != nil || count != 1 {
		t.Fatalf("outbox count = %d (err %v), want 1", count, err)
	}
}

// RED 2d: a node deletion operation and its decommission outbox commit
// atomically; a fault rolls back the operation row.
func TestApplyNodeDeleteRollsBackOnOutboxFault(t *testing.T) {
	s, node, _ := openTest(t)

	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-nodedel-1", MessageType: "C2A_NODE_DECOMMISSION",
		NodeID: "node-1", SemanticPayload: `{"stale":true}`,
	}); err != nil {
		t.Fatalf("pre-arm outbox: %v", err)
	}

	err := s.ApplyNodeDelete(store.NodeDeletionOperation{
		ID: "nodedel-1", NodeID: node.ID, Status: "PENDING", Mode: "normal",
	}, store.ControlOutboxItem{
		OperationID: "op-nodedel-1", MessageType: "C2A_NODE_DECOMMISSION",
		NodeID: "node-1", SemanticPayload: `{"node_id":"node-1"}`,
	})
	if err == nil {
		t.Fatal("ApplyNodeDelete with conflicting outbox succeeded, want fault")
	}
	if _, err := s.GetNodeDeletionOperation("nodedel-1"); err == nil {
		t.Fatal("node deletion operation survived a failed transaction")
	}
}
