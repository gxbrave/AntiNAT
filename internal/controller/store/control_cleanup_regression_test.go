package store

import (
	"fmt"
	"testing"
)

// RED: inbox replay tombstones are bounded per sweep. The controller must not
// hold an unbounded write transaction while trimming an old message backlog.
func TestControlInboxReplayCleanupIsBounded(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 2_000)
	for i := 0; i < 4; i++ {
		if _, err := s.RecordControlInbox(ControlInboxItem{
			MessageID:       fmt.Sprintf("replay-message-%d", i),
			NodeID:          "cleanup-node",
			MessageType:     "probe_result",
			OperationID:     fmt.Sprintf("probe-%d", i),
			SemanticPayload: fmt.Sprintf(`{"probe_id":"probe-%d"}`, i),
			State:           "RECEIVED",
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetControlInboxState(fmt.Sprintf("replay-message-%d", i), "PROCESSED"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}

	removed, err := s.DeleteControlInboxBeforeLimit(2_000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed %d replay rows, want bounded batch of 2", removed)
	}
	remaining, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox`)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining replay rows = %d, want 2", remaining)
	}
}

// An A2C receipt is the semantic acknowledgement for the controller outbox;
// replay-window cleanup must not discard a SEMANTIC_ACKED command before that
// receipt arrives.
func TestControlInboxReplayCleanupRetainsUnacknowledgedOutbox(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 2_000)
	const operationID = "unacknowledged-receipt-op"
	if err := s.EnqueueControlOutbox(ControlOutboxItem{
		OperationID: operationID, MessageType: "probe_arm", NodeID: "cleanup-node", SemanticPayload: "arm",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimControlOutbox("cleanup-node", "session-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent(operationID, "probe_arm", "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlSemanticACK(operationID, "probe_arm", "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE control_outbox SET updated_at = 1 WHERE operation_id = ?`, operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteControlInboxBeforeLimit(2_000, 2); err != nil {
		t.Fatal(err)
	}
	item, err := s.ControlOutboxItemByOperation(operationID, "probe_arm")
	if err != nil {
		t.Fatalf("unacknowledged outbox lookup: %v", err)
	}
	if item.State != "SEMANTIC_ACKED" {
		t.Fatalf("outbox state = %q, want SEMANTIC_ACKED", item.State)
	}
}
