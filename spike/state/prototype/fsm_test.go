package state

import (
	"errors"
	"testing"
)

// Q1 adversarial FSM tests. Written against the pre-repair control.go API,
// these assertions first demonstrated the durable receipt/phase-fencing
// bypasses (premature receipt GC, double claim, claim-after-ACK,
// ACK-without-SENT, unfenced stale overwrite, cross-session receipt GC, and
// duplicate receipt all succeeded without error). The repair makes the FSM
// fail closed: every transition requires its exact predecessor, every mutation
// is epoch/session fenced, and a durable receipt is bound to the current
// session/epoch and to a SEMANTIC_ACKED row.

func TestPrematureReceiptCannotGCPendingOperation(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "operation-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("premature receipt error = %v, want ErrIllegalPhase", err)
	}
	if !store.OutboxContains("operation-1") {
		t.Fatal("premature receipt garbage-collected a PENDING operation")
	}
}

func TestDoubleClaimIsAnIllegalPhaseRewrite(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "operation-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("double claim error = %v, want ErrIllegalPhase", err)
	}
}

func TestClaimAfterSemanticACKIsAnIllegalPhaseRewrite(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	driveToACK(t, store, 1, "session-1", "operation-1")
	if err := store.ClaimOutbox(1, "session-1", "operation-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("claim after semantic ACK error = %v, want ErrIllegalPhase", err)
	}
}

func TestSemanticACKWithoutSentPhaseFailsClosed(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	// A semantic ACK from PENDING (never claimed, never sent) must be illegal.
	if err := store.AcceptSemanticACK(1, "session-1", "operation-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("ACK from PENDING error = %v, want ErrIllegalPhase", err)
	}
	if err := store.ClaimOutbox(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	// A semantic ACK from CLAIMED (never sent) must also be illegal.
	if err := store.AcceptSemanticACK(1, "session-1", "operation-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("ACK from CLAIMED error = %v, want ErrIllegalPhase", err)
	}
}

func TestStaleWriterCannotOverwriteCurrentSemanticResult(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(5, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(5, "session-a", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(6, "session-b"); err != nil {
		t.Fatal(err)
	}
	// A stale writer (old session not yet exited) must not write state.
	if err := store.RecordAndQueueResult(5, "session-a", "operation-1", "STALE_OVERWRITE"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale-session write error = %v, want ErrStaleSession", err)
	}
	result, err := store.ResultForSession(6, "session-b", "operation-1")
	if err != nil {
		t.Fatal(err)
	}
	if result != "APPLIED" {
		t.Fatalf("result after stale write attempt = %q, want APPLIED", result)
	}
}

func TestSameSessionConflictOverwriteFailsClosed(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	// The same session must not overwrite a persisted result with a different
	// value; that is stale-writer style corruption of semantic state.
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "DIFFERENT"); !errors.Is(err, ErrStaleWriter) {
		t.Fatalf("conflicting overwrite error = %v, want ErrStaleWriter", err)
	}
}

func TestReceiptedOperationCannotResurrect(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	driveToACK(t, store, 1, "session-1", "operation-1")
	if err := store.AcceptReceipt(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("re-record after receipt error = %v, want ErrAlreadyReceipted", err)
	}
}

func TestCrossSessionReceiptCannotGCAnotherSessionsOperation(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(10, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(10, "session-a", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(11, "session-b"); err != nil {
		t.Fatal(err)
	}
	driveToACK(t, store, 11, "session-b", "operation-1")
	// A receipt presented with a stale session must not GC the operation.
	if err := store.AcceptReceipt(10, "session-a", "operation-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale-session receipt error = %v, want ErrStaleSession", err)
	}
	if !store.OutboxContains("operation-1") {
		t.Fatal("stale-session receipt garbage-collected the current session operation")
	}
}

func TestReceiptRequiresSemanticACK(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "operation-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("receipt from SENT error = %v, want ErrIllegalPhase", err)
	}
	if !store.OutboxContains("operation-1") {
		t.Fatal("receipt from SENT garbage-collected an unacked operation")
	}
}

func TestDuplicateReceiptFailsClosed(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	driveToACK(t, store, 1, "session-1", "operation-1")
	if err := store.AcceptReceipt(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "operation-1"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("duplicate receipt error = %v, want ErrAlreadyReceipted", err)
	}
}

func TestOutboxFSMForwardWalkEnforcesEveryPhase(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(1, "session-1", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	assertOutboxState(t, store, "PENDING", "operation-1")
	if err := store.ClaimOutbox(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	assertOutboxState(t, store, "CLAIMED", "operation-1")
	if err := store.MarkOutboxSent(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	assertOutboxState(t, store, "SENT", "operation-1")
	if err := store.AcceptSemanticACK(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	assertOutboxState(t, store, "SEMANTIC_ACKED", "operation-1")
	if !store.OutboxContains("operation-1") {
		t.Fatal("semantic ACK must not garbage-collect before durable receipt")
	}
	if err := store.AcceptReceipt(1, "session-1", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if store.OutboxContains("operation-1") {
		t.Fatal("durable receipt must garbage-collect the outbox row")
	}
}

// driveToACK advances an operation to SEMANTIC_ACKED using the strict FSM.
func driveToACK(t *testing.T, store *Store, epoch uint64, sessionID, operationID string) {
	t.Helper()
	if err := store.ClaimOutbox(epoch, sessionID, operationID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(epoch, sessionID, operationID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(epoch, sessionID, operationID); err != nil {
		t.Fatal(err)
	}
}

func assertOutboxState(t *testing.T, store *Store, want, operationID string) {
	t.Helper()
	got, present, err := store.OutboxState(operationID)
	if err != nil {
		t.Fatal(err)
	}
	if !present || got != want {
		t.Fatalf("outbox state = %q present=%v, want %q present=true", got, present, want)
	}
}
