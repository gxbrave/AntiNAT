// P14 repair-2 L-B store-level tests: the cleanup-only enqueue guard must also
// refuse `probe_outcome` and `restore_result` rows, and the outbox delivery
// denial must schedule a bounded backoff instead of re-claiming the same row on
// every pump tick. RED first: on the pre-fix code EnqueueControlOutbox accepts
// probe_outcome/restore_result for a cleanup-only node and QueueProbeOutcome
// enqueues without error.
package store

import (
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestCleanupOnlyNodeRefusesProbeOutcomeRestoreResultEnqueue: a cleanup-only
// (tombstoned) node must NOT accept probe_outcome / restore_result at ENQUEUE
// time. Before repair-2 the cleanupOnlyForbiddenTypes set omitted both, so
// EnqueueControlOutbox accepted them and the outbox pump was left to refuse +
// requeue them every tick (the claim/requeue spin).
func TestCleanupOnlyNodeRefusesProbeOutcomeRestoreResultEnqueue(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateNode(Node{ID: "node-clean-lb", Name: "clean-lb"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNodeCleanupTombstone(NodeCleanupTombstone{
		NodeID: "node-clean-lb", OperationID: "tomb-lb", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, mt := range []string{"probe_outcome", "restore_result"} {
		if err := s.EnqueueControlOutbox(ControlOutboxItem{
			OperationID: "op-" + mt, MessageType: mt, NodeID: "node-clean-lb",
			SemanticPayload: `{}`,
		}); err == nil {
			t.Fatalf("EnqueueControlOutbox(%q) accepted for a cleanup-only node", mt)
		}
	}
	// node_decommission remains the only allowed cleanup-only content.
	if err := s.EnqueueControlOutbox(ControlOutboxItem{
		OperationID: "op-decom-lb", MessageType: "node_decommission", NodeID: "node-clean-lb",
		SemanticPayload: `{}`,
	}); err != nil {
		t.Fatalf("node_decommission refused for cleanup-only node: %v", err)
	}
}

// TestQueueProbeOutcomeRefusedForCleanupOnlyNode: the probe-outcome insert
// path (which bypasses EnqueueControlOutbox and inserts its control_outbox row
// directly) runs the SAME enqueue guard inside its transaction. For a
// cleanup-only/tombstoned node it must refuse the whole delivery (the
// transaction rolls back), never leave a PENDING probe_outcome row that the
// pump would re-claim forever.
func TestQueueProbeOutcomeRefusedForCleanupOnlyNode(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateNode(Node{ID: "node-clean-lbp", Name: "clean-lbp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "fwd-lbp", NodeID: "node-clean-lbp", Name: "fb", Protocol: "tcp",
		CurrentActivationID: "act-lbp", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	createR13TerminalProbeForNode(t, s, "probe-lbp", "node-clean-lbp", "fwd-lbp", "act-lbp", 10)
	if err := s.CreateNodeCleanupTombstone(NodeCleanupTombstone{
		NodeID: "node-clean-lbp", OperationID: "tomb-lbp", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueueProbeOutcome("probe-lbp", protocol.OutcomeRejected); err == nil {
		t.Fatal("QueueProbeOutcome enqueued a probe_outcome for a cleanup-only node")
	}
	// The refused delivery must not leak a PENDING outbox row.
	if _, err := s.ControlOutboxItemByOperation("probe-lbp", "probe_outcome"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("probe_outcome row leaked for cleanup-only node: %v", err)
	}
}

// TestDeliveryDeniedRequeueSchedulesBackoff: when the outbox pump refuses a
// row at delivery time it requeues it with a FUTURE retry_after_unix, so the
// claim query excludes it until the bounded backoff elapses. On the pre-fix
// code the requeue left the row immediately claimable and the pump re-claimed
// it every tick.
func TestDeliveryDeniedRequeueSchedulesBackoff(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateNode(Node{ID: "node-lb-backoff", Name: "lb-backoff"}); err != nil {
		t.Fatal(err)
	}
	owner, err := s.AcquireControlOwner("node-lb-backoff", 0, "session-lb-backoff")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueControlOutbox(ControlOutboxItem{
		OperationID: "op-lb-backoff", MessageType: "desired", NodeID: "node-lb-backoff",
		SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimControlOutboxOwned(owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].RetryAfterUnix != 0 {
		t.Fatalf("claimed = %+v, want one immediately-claimable row", claimed)
	}
	if err := s.RequeueControlOutboxItemOwned("op-lb-backoff", "desired", owner); err != nil {
		t.Fatal(err)
	}
	item, err := s.ControlOutboxItemByOperation("op-lb-backoff", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "PENDING" {
		t.Fatalf("requeued state = %q, want PENDING", item.State)
	}
	if item.RetryAfterUnix <= now() {
		t.Fatalf("requeued row retry_after_unix = %d is not in the future (would be re-claimed next tick)", item.RetryAfterUnix)
	}
}
