package localstate

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// Story 3 RED: durable inbox/outbox journals. Duplicate message/type/hash,
// old revision (stale epoch/session), result resend and receipt GC cases all
// fail closed before the journal.go GREEN implementation.

func TestAdvanceSessionRejectsLowerEpoch(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(5, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(4, "session-old"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("lower-epoch advance error = %v, want ErrStaleSession", err)
	}
	if err := store.AdvanceSession(5, "session-other"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("same-epoch different-session advance error = %v, want ErrStaleSession", err)
	}
	if err := store.AdvanceSession(5, "session-a"); err != nil {
		t.Fatalf("idempotent same-session advance error = %v", err)
	}
}

func TestReceiveCommandDuplicateSameIdentityIsIdempotent(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	dup, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion))
	if err != nil {
		t.Fatal(err)
	}
	if dup {
		t.Fatal("first delivery reported duplicate")
	}
	dup, err = store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion))
	if err != nil {
		t.Fatalf("same identity redelivery error = %v, want cached duplicate", err)
	}
	if !dup {
		t.Fatal("same identity redelivery did not report duplicate")
	}
}

func TestReceiveCommandConflictingIdentityFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-2", "msg-1", "desired", "hash-DIFFERENT", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("same message ID different payload hash error = %v, want ErrMessageConflict", err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-2", "msg-1", "DIFFERENT-TYPE", "hash-1", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("same message ID different type error = %v, want ErrMessageConflict", err)
	}
}

func TestOperationInboxFSMEnforcesPhases(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	phase, ok, err := store.OperationPhase("op-1")
	if err != nil || !ok || phase != "RECEIVED" {
		t.Fatalf("phase after receive = %q ok=%v err=%v, want RECEIVED", phase, ok, err)
	}
	// Skip over INTENT_PERSISTED straight to APPLYING must fail closed.
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("skip-to-applying error = %v, want ErrIllegalPhase", err)
	}
	// Complete from RECEIVED (never INTENT_PERSISTED/APPLYING) must fail.
	if err := store.CompleteOperation(1, "session-1", "op-1", []byte("result")); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("complete-from-RECEIVED error = %v, want ErrIllegalPhase", err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Applying -> NACKED is legal.
	if err := store.NackOperation(1, "session-1", "op-1", "cannot reach target"); err != nil {
		t.Fatal(err)
	}
	phase, _, err = store.OperationPhase("op-1")
	if err != nil || phase != "NACKED" {
		t.Fatalf("phase after nack = %q err=%v, want NACKED", phase, err)
	}
	// APPLIED -> NACKED (a completed operation regressing) must fail closed.
	if _, err := store.ReceiveCommand(1, "session-1", "op-2", "msg-2", "desired", "hash-2", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOperation(1, "session-1", "op-2", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.NackOperation(1, "session-1", "op-2", "late"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("nack-after-applied error = %v, want ErrIllegalPhase", err)
	}
}

func TestCompleteOperationQueuesOutboxResult(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOperation(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("outbox after complete = %q present=%v err=%v, want PENDING", state, present, err)
	}
	result, err := store.ResultForOperation(1, "session-1", "op-1")
	if err != nil || string(result) != "deleted" {
		t.Fatalf("result = %q err=%v, want deleted", result, err)
	}
}

func TestStaleSessionMutationFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(2, "session-b"); err != nil {
		t.Fatal(err)
	}
	// A stale writer from session-a must not mutate state on session-b.
	if err := store.QueueResult(1, "session-a", "op-1", []byte("APPLIED")); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale-session write error = %v, want ErrStaleSession", err)
	}
	if _, err := store.ReceiveCommand(1, "session-a", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale-session receive error = %v, want ErrStaleSession", err)
	}
}

func TestOldEpochReceiptRejectedAndResultResentOnNewSession(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-a", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-a", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-a", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(2, "session-b"); err != nil {
		t.Fatal(err)
	}
	// Old-epoch semantic ACK and receipt are rejected: the new session
	// re-signs the same semantic result instead of repeating the side effect.
	if err := store.AcceptSemanticACK(1, "session-a", "op-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session ACK error = %v, want ErrStaleSession", err)
	}
	if err := store.AcceptReceipt(1, "session-a", "op-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session receipt error = %v, want ErrStaleSession", err)
	}
	// The durable semantic result is still available for resend.
	result, err := store.ResultForOperation(2, "session-b", "op-1")
	if err != nil || string(result) != "deleted" {
		t.Fatalf("result resend = %q err=%v, want deleted", result, err)
	}
	// The new session requeues the same semantic result without a side effect.
	n, err := store.RequeueOutboxForSession(2, "session-b")
	if err != nil || n != 1 {
		t.Fatalf("requeue count = %d err=%v, want 1", n, err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("outbox after requeue = %q present=%v err=%v, want PENDING", state, present, err)
	}
}

func TestOutboxForwardWalkAndIllegalTransitions(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("result")); err != nil {
		t.Fatal(err)
	}
	// Premature receipt from PENDING must fail closed and not GC.
	if err := store.AcceptReceipt(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("premature receipt error = %v, want ErrIllegalPhase", err)
	}
	if !store.OutboxContains("op-1") {
		t.Fatal("premature receipt garbage-collected a PENDING operation")
	}
	// Double claim must fail closed.
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("double claim error = %v, want ErrIllegalPhase", err)
	}
	// ACK before SENT must fail closed.
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("ACK from CLAIMED error = %v, want ErrIllegalPhase", err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Receipt from SENT (never semantically ACKed) must fail closed.
	if err := store.AcceptReceipt(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("receipt from SENT error = %v, want ErrIllegalPhase", err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if !store.OutboxContains("op-1") {
		t.Fatal("semantic ACK must not GC before durable receipt")
	}
	// Claim after ACK must fail closed.
	if err := store.ClaimOutbox(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("claim after ACK error = %v, want ErrIllegalPhase", err)
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if store.OutboxContains("op-1") {
		t.Fatal("durable receipt must GC the outbox row")
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("duplicate receipt error = %v, want ErrAlreadyReceipted", err)
	}
}

func TestReceiptGCBlocksResurrection(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	ok, err := store.ReceiptExists("op-1")
	if err != nil || !ok {
		t.Fatalf("receipt tombstone present=%v err=%v, want durable", ok, err)
	}
	// A replayed record after durable receipt must not resurrect the outbox.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("re-record after receipt error = %v, want ErrAlreadyReceipted", err)
	}
	if store.OutboxContains("op-1") {
		t.Fatal("replayed record after receipt resurrected the outbox row")
	}
	if _, err := store.ResultForOperation(1, "session-1", "op-1"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("result lookup after receipt error = %v, want ErrAlreadyReceipted", err)
	}
}

func TestQueueResultStaleWriterFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("APPLIED")); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("DIFFERENT")); !errors.Is(err, ErrStaleWriter) {
		t.Fatalf("conflicting overwrite error = %v, want ErrStaleWriter", err)
	}
	if result, _ := store.ResultForOperation(1, "session-1", "op-1"); !bytes.Equal(result, []byte("APPLIED")) {
		t.Fatalf("result after conflicting write = %q, want APPLIED", result)
	}
}

// Repair-cycle Q1 RED: re-recording the same semantic result while its outbox
// row is in flight (CLAIMED/SENT/SEMANTIC_ACKED, no durable receipt yet) must
// be idempotent, leave the row untouched, and not disturb the subsequent
// receipt path. Before the fix, recordResultAndQueue returned ErrIllegalPhase
// for any non-PENDING same-payload row and the reconcile control loop died.
func TestQueueResultIdempotentForInFlightOutboxRow(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Re-record while CLAIMED: already durably queued, must not fail.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatalf("re-record while CLAIMED error = %v, want nil (idempotent)", err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Re-record while SENT: idempotent, row untouched.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatalf("re-record while SENT error = %v, want nil (idempotent)", err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "SENT" {
		t.Fatalf("outbox after re-record while SENT = %q present=%v err=%v, want SENT", state, present, err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Re-record while SEMANTIC_ACKED: idempotent, row untouched.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatalf("re-record while SEMANTIC_ACKED error = %v, want nil (idempotent)", err)
	}
	state, present, err = store.OutboxState("op-1")
	if err != nil || !present || state != "SEMANTIC_ACKED" {
		t.Fatalf("outbox after re-record while SEMANTIC_ACKED = %q present=%v err=%v, want SEMANTIC_ACKED", state, present, err)
	}
	// The subsequent receipt path must still work on the untouched row.
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatalf("receipt after in-flight re-record error = %v", err)
	}
	if store.OutboxContains("op-1") {
		t.Fatal("durable receipt must GC the outbox row")
	}
}
