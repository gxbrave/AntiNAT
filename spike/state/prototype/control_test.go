package state

import (
	"errors"
	"testing"
)

func TestEpochFencingRejectsStaleInboundAndOutboundWork(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(7, "session-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(8, "session-new"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(7, "session-old", "message-old", "desired", "hash-a"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale inbound error = %v, want ErrStaleSession", err)
	}
	if err := store.ClaimOutbox(7, "session-old", "operation-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale outbound error = %v, want ErrStaleSession", err)
	}
	if _, err := store.ReceiveCommand(8, "session-new", "message-new", "desired", "hash-b"); err != nil {
		t.Fatal(err)
	}
	dir := store.Dir()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ReceiveCommand(7, "session-old", "message-after-restart", "desired", "hash-c"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("persisted stale inbound error = %v, want ErrStaleSession", err)
	}
}

func TestOldEpochACKResendsSemanticResultOnNewSession(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(20, "session-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAndQueueResult(20, "session-old", "operation-1", "APPLIED"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(21, "session-new"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(20, "session-old", "operation-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old epoch ACK error = %v, want ErrStaleSession", err)
	}
	result, err := store.ResultForSession(21, "session-new", "operation-1")
	if err != nil {
		t.Fatal(err)
	}
	if result != "APPLIED" {
		t.Fatalf("resent semantic result = %q, want APPLIED", result)
	}
	// The new session re-envelopes the same semantic result through the strict
	// FSM without repeating the side effect: claim -> sent -> semantic ACK.
	if err := store.ClaimOutbox(21, "session-new", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(21, "session-new", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(21, "session-new", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if !store.OutboxContains("operation-1") {
		t.Fatal("semantic ACK garbage-collected outbox before durable receipt")
	}
	if err := store.AcceptReceipt(21, "session-new", "operation-1"); err != nil {
		t.Fatal(err)
	}
	if store.OutboxContains("operation-1") {
		t.Fatal("outbox remains after durable receipt")
	}
}

func TestDuplicateMessageIDConflictsFailClosed(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.ReceiveCommand(1, "session-1", "message-1", "desired", "hash-a")
	if err != nil || duplicate {
		t.Fatalf("first delivery: duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = store.ReceiveCommand(1, "session-1", "message-1", "desired", "hash-a")
	if err != nil || !duplicate {
		t.Fatalf("identical duplicate: duplicate=%v err=%v", duplicate, err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "message-1", "desired", "hash-conflict"); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("conflicting duplicate error = %v, want ErrMessageConflict", err)
	}
}
