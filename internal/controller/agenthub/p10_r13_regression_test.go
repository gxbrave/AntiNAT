package agenthub

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func r13CorrelationSession(t *testing.T) (*ControlSession, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateNode(store.Node{ID: "node-r13", Name: "node-r13"}); err != nil {
		t.Fatal(err)
	}
	h := &Hub{store: st}
	return &ControlSession{hub: h, nodeID: "node-r13", session: "session-r13"}, st
}

func enqueueR13CorrelationBacklog(t *testing.T, st *store.Store, target string) {
	t.Helper()
	for i := 0; i < 256; i++ {
		if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
			OperationID: fmt.Sprintf("aa-%03d", i), MessageType: "desired", NodeID: "node-r13", SemanticPayload: `{}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: target, MessageType: "desired", NodeID: "node-r13", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
}

// R13 RED: result correlation is a deterministic indexed lookup, not a scan
// of the lexicographically first 256 active rows. A valid result for row 257
// must remain live and must not terminate the control session.
func TestR13ResultCorrelationBeyond256Rows(t *testing.T) {
	session, st := r13CorrelationSession(t)
	const target = "zz-target-result"
	enqueueR13CorrelationBacklog(t, st, target)
	commandID := security.MessageID(target, "desired")
	agentOperation := hex.EncodeToString(commandID[:])
	resultID := security.MessageID(agentOperation, "operation_complete")
	row, gotOperation, err := session.hub.matchOutboxRow(session, resultID, "operation_complete")
	if err != nil {
		t.Fatalf("row 257 result did not correlate: %v", err)
	}
	if row.OperationID != target || gotOperation != agentOperation {
		t.Fatalf("correlated row/op = %q/%q, want %q/%q", row.OperationID, gotOperation, target, agentOperation)
	}
}

// R13 RED: command-receipt correlation uses the exact deterministic command
// message id and must work independently of outbox backlog ordering.
func TestR13ReceiptCorrelationBeyond256Rows(t *testing.T) {
	session, st := r13CorrelationSession(t)
	const target = "zz-target-receipt"
	enqueueR13CorrelationBacklog(t, st, target)
	commandID := security.MessageID(target, "desired")
	commandHex := hex.EncodeToString(commandID[:])
	row, _, err := session.hub.matchOutboxRowByCommandMessageID(session, commandHex)
	if err != nil {
		t.Fatalf("row 257 receipt did not correlate: %v", err)
	}
	if row.OperationID != target {
		t.Fatalf("receipt correlated operation %q, want %q", row.OperationID, target)
	}
}

// R13 RED: a signed message_receipt payload still needs schema-aware semantic
// JSON validation. Signature/framing validity cannot make duplicate or unknown
// fields unambiguous.
func TestR13ReceiptSemanticJSONIsStrict(t *testing.T) {
	for _, raw := range []string{
		`{"operation_id":"first","operation_id":"second"}`,
		`{"operation_id":"first","unknown":true}`,
		`{"operation_id":"first"} {}`,
	} {
		if got, err := operationIDFromReceipt([]byte(raw)); err == nil {
			t.Fatalf("ambiguous receipt %s accepted as %q", raw, got)
		}
	}
}
