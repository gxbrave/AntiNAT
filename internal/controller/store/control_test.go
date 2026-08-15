package store

import (
	"errors"
	"path/filepath"
	"sync"
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

// An outbox insert is the durable intent boundary. It must always start at
// PENDING; callers cannot manufacture an already-sent or already-acknowledged
// row that bypasses delivery and receipt fencing.
func TestControlOutboxInsertAlwaysStartsPending(t *testing.T) {
	s := openControlStore(t)
	if err := s.EnqueueControlOutbox(ControlOutboxItem{
		OperationID: "op-initial-state", MessageType: "desired", NodeID: "node-a",
		SemanticPayload: `{"ok":true}`, State: "SEMANTIC_ACKED",
	}); err != nil {
		t.Fatal(err)
	}
	row, err := s.ControlOutboxItemByOperation("op-initial-state", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "PENDING" {
		t.Fatalf("new outbox state = %q, want PENDING", row.State)
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

func TestControlOutboxConcurrentClaimsHaveOneOwner(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-claim-race", "desired", "node-a")

	start := make(chan struct{})
	var wg sync.WaitGroup
	type result struct {
		session string
		items   []ControlOutboxItem
		err     error
	}
	results := make(chan result, 2)
	for _, session := range []string{"session-1", "session-2"} {
		wg.Add(1)
		go func(session string) {
			defer wg.Done()
			<-start
			items, err := s.ClaimControlOutbox("node-a", session, 10)
			results <- result{session: session, items: items, err: err}
		}(session)
	}
	close(start)
	wg.Wait()
	close(results)

	claimed := 0
	owners := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("claim by %s: %v", result.session, result.err)
		}
		if len(result.items) != 0 {
			owners++
			claimed += len(result.items)
		}
	}
	if owners != 1 || claimed != 1 {
		t.Fatalf("concurrent claim owners=%d claimed=%d, want 1/1", owners, claimed)
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

// Session validation and the state CAS must be one operation. Otherwise an
// old session can pass a pre-check before reconnect, then advance a row that
// the new session has already claimed.
func TestControlOutboxSemanticACKUsesAtomicSessionAndPhaseCAS(t *testing.T) {
	s := openControlStore(t)
	mustEnqueue(t, s, "op-race", "desired", "node-a")
	if _, err := s.ClaimControlOutbox("node-a", "session-1", 10); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-race", "desired", "session-1"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RequeueControlOutboxForSession("node-a", "session-2"); err != nil || n != 1 {
		t.Fatalf("requeue = %d (err %v), want one row", n, err)
	}
	if _, err := s.ClaimControlOutbox("node-a", "session-2", 10); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("op-race", "desired", "session-2"); err != nil {
		t.Fatal(err)
	}

	if err := s.AcceptControlSemanticACK("op-race", "desired", "session-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session semantic ACK = %v, want ErrStaleSession", err)
	}
	row, err := s.ControlOutboxItemByOperation("op-race", "desired")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "SENT" {
		t.Fatalf("row state after stale ACK = %q, want SENT", row.State)
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

// Duplicate deliveries can arrive concurrently when a reconnect overlaps a
// retry. The read/check/insert must be one durable operation: one caller
// records the inbox row and every other caller observes a cached duplicate,
// rather than surfacing a UNIQUE constraint error.
func TestControlInboxConcurrentDuplicateDeliveryIsIdempotent(t *testing.T) {
	s := openControlStore(t)
	item := ControlInboxItem{
		MessageID: "msg-concurrent", NodeID: "node-a", MessageType: "desired_result",
		OperationID: "op-concurrent", SemanticPayload: `{"ok":true}`,
	}

	const callers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	duplicates := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			duplicate, err := s.RecordControlInbox(item)
			if err != nil {
				errs <- err
				return
			}
			duplicates <- duplicate
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(duplicates)

	for err := range errs {
		t.Fatalf("concurrent inbox delivery: %v", err)
	}
	firsts := 0
	dups := 0
	for duplicate := range duplicates {
		if duplicate {
			dups++
		} else {
			firsts++
		}
	}
	if firsts != 1 || dups != callers-1 {
		t.Fatalf("concurrent inbox results: firsts=%d duplicates=%d, want 1/%d", firsts, dups, callers-1)
	}
}

func TestControlInboxDuplicatePreservesNodeAndOperationBinding(t *testing.T) {
	s := openControlStore(t)
	first := ControlInboxItem{
		MessageID: "msg-binding", NodeID: "node-a", MessageType: "operation_complete",
		OperationID: "op-a", SemanticPayload: `{"ok":true}`,
	}
	if duplicate, err := s.RecordControlInbox(first); err != nil || duplicate {
		t.Fatalf("first record = duplicate:%v err:%v", duplicate, err)
	}

	for name, conflicting := range map[string]ControlInboxItem{
		"node": func() ControlInboxItem {
			item := first
			item.NodeID = "node-b"
			return item
		}(),
		"operation": func() ControlInboxItem {
			item := first
			item.OperationID = "op-b"
			return item
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.RecordControlInbox(conflicting); !errors.Is(err, ErrMessageConflict) {
				t.Fatalf("binding conflict = %v, want ErrMessageConflict", err)
			}
		})
	}
}

func TestControlInboxDuplicateHandlesLegacyNullOperationID(t *testing.T) {
	s := openControlStore(t)
	if _, err := s.db.Exec(
		`INSERT INTO control_inbox
		    (message_id, node_id, message_type, semantic_payload, state,
		     operation_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'RECEIVED', NULL, ?, ?)`,
		"msg-legacy-null", "node-a", "desired_result", `{"ok":true}`, now(), now(),
	); err != nil {
		t.Fatalf("insert legacy inbox row: %v", err)
	}
	duplicate, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: "msg-legacy-null", NodeID: "node-a", MessageType: "desired_result",
		SemanticPayload: `{"ok":true}`,
	})
	if err != nil || !duplicate {
		t.Fatalf("legacy null operation duplicate = %v (err %v), want true/nil", duplicate, err)
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
