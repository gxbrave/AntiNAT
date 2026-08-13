package store

import (
	"errors"
	"path/filepath"
	"testing"
)

// P08 Story 5 RED: controller-side outbox FSM transitions (frozen
// state-model §3.1) and control inbox dedup (frozen protocol.md §3.5).
// P06 created the control_outbox/control_inbox tables; these methods are the
// P08-declared store extension driving claim/send/ack/receipt per session.

func openControlStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustEnqueue(t *testing.T, s *Store, opID, msgType, nodeID string) {
	t.Helper()
	if err := s.EnqueueControlOutbox(ControlOutboxItem{
		OperationID: opID, MessageType: msgType, NodeID: nodeID,
		SemanticPayload: `{"op":"` + opID + `"}`, State: "PENDING",
	}); err != nil {
		t.Fatalf("EnqueueControlOutbox: %v", err)
	}
}

// RED 5a: claiming advances PENDING -> CLAIMED bound to the session and
// returns the claimed items.
func TestControlOutboxClaim(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-1", "desired", "node-a")
	mustEnqueue(t, s, "op-2", "desired", "node-a")

	items, err := s.ClaimControlOutbox("node-a", "session-1", 10)
	if err != nil {
		t.Fatalf("ClaimControlOutbox: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("claimed = %d, want 2", len(items))
	}
	got, err := s.ControlOutboxItemByOperation("op-1", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "CLAIMED" {
		t.Fatalf("state after claim = %q, want CLAIMED", got.State)
	}
}

// RED 5b: the outbox FSM is single-step: SENT -> SEMANTIC_ACKED -> RECEIPTED
// (GC), and illegal transitions fail closed.
func TestControlOutboxFSMTransitions(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-1", "desired", "node-a")
	if _, err := s.ClaimControlOutbox("node-a", "session-1", 10); err != nil {
		t.Fatal(err)
	}
	// CLAIMED -> SENT.
	if err := s.MarkControlOutboxSent("op-1", "desired", "session-1"); err != nil {
		t.Fatalf("MarkControlOutboxSent: %v", err)
	}
	// Receipt before semantic ACK is illegal.
	if err := s.AcceptControlReceipt("op-1", "desired", "session-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("premature receipt = %v, want ErrIllegalPhase", err)
	}
	// SENT -> SEMANTIC_ACKED.
	if err := s.AcceptControlSemanticACK("op-1", "desired", "session-1"); err != nil {
		t.Fatalf("AcceptControlSemanticACK: %v", err)
	}
	// SEMANTIC_ACKED -> RECEIPTED (row GC'd).
	if err := s.AcceptControlReceipt("op-1", "desired", "session-1"); err != nil {
		t.Fatalf("AcceptControlReceipt: %v", err)
	}
	if _, err := s.ControlOutboxItemByOperation("op-1", "desired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("receipted row not GC'd: %v", err)
	}
	// Double receipt fails closed.
	if err := s.AcceptControlReceipt("op-1", "desired", "session-1"); err == nil {
		t.Fatal("double receipt succeeded")
	}
}

// RED 5c: transitions are session-bound — an old session cannot advance a row
// claimed by the current session.
func TestControlOutboxSessionBound(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-1", "desired", "node-a")
	if _, err := s.ClaimControlOutbox("node-a", "session-1", 10); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-1", "desired", "session-OLD"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session sent = %v, want ErrStaleSession", err)
	}
	if err := s.AcceptControlSemanticACK("op-1", "desired", "session-OLD"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session ack = %v, want ErrStaleSession", err)
	}
}

// RED 5d: a new session requeues non-receipted rows to PENDING for redelivery
// (semantic resend, frozen §6.1: same operation re-enveloped).
func TestControlOutboxRequeueForNewSession(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-1", "desired", "node-a")
	if _, err := s.ClaimControlOutbox("node-a", "session-1", 10); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-1", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	n, err := s.RequeueControlOutboxForSession("node-a", "session-2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("requeued = %d, want 1", n)
	}
	got, err := s.ControlOutboxItemByOperation("op-1", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "PENDING" {
		t.Fatalf("state after requeue = %q, want PENDING", got.State)
	}
}

// FIX1 RED (F1-a): a new session requeues only in-flight rows (CLAIMED/SENT).
// A SEMANTIC_ACKED row is the controller's own proof that the agent's result
// was already processed and the C2A receipt was written; requeuing it
// re-delivers an operation the agent may already have durably receipted
// (journal tombstone), which fails the agent closed with ErrAlreadyReceipted
// and kills the session (P08-QUALITY F1, reproduced in /tmp/p08-probe).
func TestControlOutboxRequeueSkipsSemanticAcked(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-1", "desired", "node-a") // will be SEMANTIC_ACKED
	mustEnqueue(t, s, "op-2", "desired", "node-a") // will be SENT
	if _, err := s.ClaimControlOutbox("node-a", "session-1", 10); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-1", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-2", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlSemanticACK("op-1", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	n, err := s.RequeueControlOutboxForSession("node-a", "session-2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("requeued = %d, want 1 (only the SENT row; SEMANTIC_ACKED must not be requeued)", n)
	}
	got, err := s.ControlOutboxItemByOperation("op-1", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "SEMANTIC_ACKED" {
		t.Fatalf("op-1 state after requeue = %q, want SEMANTIC_ACKED (result already durably processed)", got.State)
	}
	got2, err := s.ControlOutboxItemByOperation("op-2", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if got2.State != "PENDING" {
		t.Fatalf("op-2 state after requeue = %q, want PENDING", got2.State)
	}
}

// FIX1 RED (F1-b store support): RebindControlOutboxSession re-binds a
// SEMANTIC_ACKED row to the session that resends the result, so the follow-up
// A2C receipt from that session can complete the GC. The FSM state is
// untouched; a rebind of a row in any other state fails closed.
func TestControlOutboxRebindSession(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-1", "desired", "node-a")
	if _, err := s.ClaimControlOutbox("node-a", "session-1", 10); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-1", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlSemanticACK("op-1", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RebindControlOutboxSession("op-1", "desired", "session-2"); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	got, err := s.ControlOutboxItemByOperation("op-1", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "SEMANTIC_ACKED" {
		t.Fatalf("state after rebind = %q, want SEMANTIC_ACKED (rebind must not advance the FSM)", got.State)
	}
	// The old session can no longer complete the GC; the new session can.
	if err := s.AcceptControlReceipt("op-1", "desired", "session-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session receipt after rebind = %v, want ErrStaleSession", err)
	}
	if err := s.AcceptControlReceipt("op-1", "desired", "session-2"); err != nil {
		t.Fatalf("new-session receipt after rebind: %v", err)
	}
	if _, err := s.ControlOutboxItemByOperation("op-1", "desired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("row not GC'd after rebind+receipt: %v", err)
	}
	// Rebind of a non-SEMANTIC_ACKED row fails closed.
	mustEnqueue(t, s, "op-2", "desired", "node-a")
	if err := s.RebindControlOutboxSession("op-2", "desired", "session-2"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("rebind of PENDING row = %v, want ErrIllegalPhase", err)
	}
	if err := s.RebindControlOutboxSession("no-such-op", "desired", "session-2"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("rebind of missing row = %v, want ErrIllegalPhase", err)
	}
}

// RED 5e: control inbox dedup — same message_id + same type + same payload is
// a cached duplicate; same message_id + different material is a fail-closed
// session conflict.
func TestControlInboxDedup(t *testing.T) {
	s := openControlStore(t)
	dup, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: "msg-1", NodeID: "node-a", MessageType: "desired_result",
		SemanticPayload: `{"ok":true}`,
	})
	if err != nil || dup {
		t.Fatalf("first record = dup:%v err:%v", dup, err)
	}
	dup, err = s.RecordControlInbox(ControlInboxItem{
		MessageID: "msg-1", NodeID: "node-a", MessageType: "desired_result",
		SemanticPayload: `{"ok":true}`,
	})
	if err != nil || !dup {
		t.Fatalf("same identity record = dup:%v err:%v, want cached duplicate", dup, err)
	}
	_, err = s.RecordControlInbox(ControlInboxItem{
		MessageID: "msg-1", NodeID: "node-a", MessageType: "desired_result",
		SemanticPayload: `{"ok":false}`, // different hash
	})
	if !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("conflicting record = %v, want ErrMessageConflict", err)
	}
	_, err = s.RecordControlInbox(ControlInboxItem{
		MessageID: "msg-1", NodeID: "node-a", MessageType: "DIFFERENT-TYPE",
		SemanticPayload: `{"ok":true}`,
	})
	if !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("different-type record = %v, want ErrMessageConflict", err)
	}
}

// RED 5f: node control state transitions.
func TestSetNodeControlState(t *testing.T) {
	s := openControlStore(t)
	if err := s.CreateNode(Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeControlState("node-a", "ONLINE"); err != nil {
		t.Fatalf("SetNodeControlState: %v", err)
	}
	n, err := s.GetNode("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if n.ControlState != "ONLINE" {
		t.Fatalf("control state = %q, want ONLINE", n.ControlState)
	}
}
