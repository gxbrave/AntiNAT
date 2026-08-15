// P08 Story 5 RED: reconnect and semantic resend. After a disconnect the
// agent re-handshakes (higher epoch), requeues un-receipted results, and
// re-envelopes the SAME operation without repeating the side effect; the
// controller re-delivers un-receipted commands without a second apply.
package control_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// RED 5h: disconnect after the result was queued but before the receipt —
// the reconnect re-envelopes the same semantic result; the handler runs
// exactly once and the controller outbox row is GC'd.
func TestReconnectResendsResultWithoutDuplicateSideEffect(t *testing.T) {
	h := newSessionHarness(t)
	var applied atomic.Int32
	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(ctx context.Context, op control.Operation) ([]byte, error) {
			applied.Add(1)
			return []byte(`{"applied":true}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Enqueue the first command; once it is applied, enqueue the second and
	// hard-kill the agent connection before any receipt completes, forcing a
	// reconnect. The second command is enqueued only after the first apply
	// so the kill never races its journaling (FIX1: the disconnect is timed
	// after processing, never inside it — a command journaled but not yet
	// applied at disconnect would be swallowed by the resend dedup).
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-1", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: `{"node_id":"` + h.nodeID + `","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Wait for the first apply, then kill the socket.
	deadline := time.Now().Add(5 * time.Second)
	for applied.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if applied.Load() == 0 {
		t.Fatal("no command applied before kill")
	}
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-2", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: `{"node_id":"` + h.nodeID + `","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}
	fix1Disconnect(t, h, client) // wait for the old controller session to unregister

	// Reconnect the SAME Client: a transport close is not terminal; the
	// subsequent handshake must reuse its durable state and pumps.
	client.Wait()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("reconnect Connect: %v", err)
	}

	// Both outbox rows must reach a terminal state: GONE (durably receipted
	// and GC'd) or SEMANTIC_ACKED (FIX1 receipt-window corner: the agent
	// durably receipted its result but the connection died before the
	// controller consumed the agent's A2C receipt — the row is retained for
	// the P14 receipt-TTL sweeper, it is never requeued/re-sent). The session
	// must stay ONLINE in every corner: the controller must never re-deliver
	// an already-receipted command (that killed the session pre-FIX1).
	deadline = time.Now().Add(8 * time.Second)
	terminal1, terminal2 := false, false
	for time.Now().Before(deadline) {
		r1, e1 := h.st.ControlOutboxItemByOperation("op-1", "desired")
		r2, e2 := h.st.ControlOutboxItemByOperation("op-2", "desired")
		terminal1 = errors.Is(e1, store.ErrNotFound) || (e1 == nil && r1.State == "SEMANTIC_ACKED")
		terminal2 = errors.Is(e2, store.ErrNotFound) || (e2 == nil && r2.State == "SEMANTIC_ACKED")
		if terminal1 && terminal2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	row1, err1 := h.st.ControlOutboxItemByOperation("op-1", "desired")
	row2, err2 := h.st.ControlOutboxItemByOperation("op-2", "desired")
	if !errors.Is(err1, store.ErrNotFound) && !(err1 == nil && row1.State == "SEMANTIC_ACKED") {
		t.Fatalf("op-1 not terminal after reconnect: err=%v state=%s", err1, row1.State)
	}
	if !errors.Is(err2, store.ErrNotFound) && !(err2 == nil && row2.State == "SEMANTIC_ACKED") {
		t.Fatalf("op-2 not terminal after reconnect: err=%v state=%s", err2, row2.State)
	}
	// Liveness: any retained (SEMANTIC_ACKED) row must coexist with an
	// ONLINE session — the pre-FIX1 code killed the session re-delivering
	// the already-receipted command and leaked the row in SENT.
	if err1 == nil || err2 == nil {
		deadline = time.Now().Add(5 * time.Second)
		online := false
		for time.Now().Before(deadline) {
			n, err := h.st.GetNode(h.nodeID)
			if err == nil && n.ControlState == "ONLINE" {
				online = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !online {
			t.Fatal("node not ONLINE while rows are retained (session killed by re-delivery?)")
		}
	}
	// Exactly two side effects across the reconnect (one per operation).
	if got := applied.Load(); got != 2 {
		t.Fatalf("applied = %d, want exactly 2 (no duplicate side effect on resend)", got)
	}
}

// RED 5i: reconnect bumps the agent's persisted epoch and the controller's.
func TestReconnectBumpsEpoch(t *testing.T) {
	h := newSessionHarness(t)
	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	epoch1, _, _ := h.ls.CurrentSession()
	client.Close()

	client2, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	epoch2, session2, _ := h.ls.CurrentSession()
	if epoch2 != epoch1+1 {
		t.Fatalf("epoch after reconnect = %d, want %d", epoch2, epoch1+1)
	}
	if session2 == "" {
		t.Fatal("empty session after reconnect")
	}
}

var _ = websocket.MessageBinary

// ---- FIX1 (P08-QUALITY F1): receipt-window corners -------------------------
//
// The controller processed an agent result (outbox row SEMANTIC_ACKED, C2A
// receipt written) but never consumed the agent's A2C receipt because the
// connection died in the RTT-scale window between the two. On reconnect the
// controller must NOT requeue the row (re-delivering a command the agent may
// already have durably receipted fails the agent closed with
// ErrAlreadyReceipted and kills the session). The setups below drive both
// stores to the exact corner state BEFORE the reconnect, so the tests are
// deterministic: the first session's pumps are quiescent (agent pump exits
// within one 100ms tick of Close; the controller unregisters the session)
// before any state is constructed, and no live pump can race the setup.

// fix1CommandPayload is the deterministic command payload used for op-1.
func fix1CommandPayload(nodeID string) string {
	return `{"node_id":"` + nodeID + `","forwards":[]}`
}

// fix1DriveControllerRowSemanticAcked enqueues op-1 and drives the controller
// outbox FSM to SEMANTIC_ACKED bound to the given session, mirroring "result
// processed + C2A receipt written; A2C receipt lost".
func fix1DriveControllerRowSemanticAcked(t *testing.T, h *sessionHarness, session string) {
	t.Helper()
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-1", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: fix1CommandPayload(h.nodeID),
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.ClaimControlOutboxOperation("op-1", "desired", session); err != nil {
		t.Fatal(err)
	}
	if err := h.st.MarkControlOutboxSent("op-1", "desired", session); err != nil {
		t.Fatal(err)
	}
	if err := h.st.AcceptControlSemanticACK("op-1", "desired", session); err != nil {
		t.Fatal(err)
	}
	// Mirror the controller having durably recorded the result that moved
	// the row (the agent's resend is then a cached duplicate, exactly as in
	// the real corner).
	if _, err := h.st.RecordControlInbox(store.ControlInboxItem{
		MessageID:       fix1ResultMessageID(),
		NodeID:          h.nodeID,
		MessageType:     "operation_complete",
		SemanticPayload: `{"applied":true}`,
		State:           "RECEIVED",
	}); err != nil {
		t.Fatal(err)
	}
}

// fix1ResultMessageID is the deterministic A2C result message id the agent
// uses for op-1 (its operation id is the hex command message id).
func fix1ResultMessageID() string {
	msgID := security.MessageID(fix1OpIDHex(), "operation_complete")
	return hex.EncodeToString(msgID[:])
}

// fix1OpIDHex is the agent-side operation id for op-1 (hex of the C2A command
// message id, mirroring the agent's inbox FSM).
func fix1OpIDHex() string {
	msgID := security.MessageID("op-1", "desired")
	return hex.EncodeToString(msgID[:])
}

// fix1DriveAgentAppliedOp1 journals op-1 through apply + outbox SENT on the
// agent (no receipt tombstone: the C2A receipt never arrived). Returns the
// agent-side operation id.
func fix1DriveAgentAppliedOp1(t *testing.T, h *sessionHarness, epoch uint64, session string) string {
	t.Helper()
	op := fix1OpIDHex()
	sum := sha256.Sum256([]byte(fix1CommandPayload(h.nodeID)))
	if _, err := h.ls.ReceiveCommand(epoch, session, op, op, "desired", hex.EncodeToString(sum[:]), "desired"); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.PersistOperationIntent(epoch, session, op); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.MarkOperationApplying(epoch, session, op); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.CompleteOperation(epoch, session, op, []byte(`{"applied":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.ClaimOutbox(epoch, session, op); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.MarkOutboxSent(epoch, session, op); err != nil {
		t.Fatal(err)
	}
	return op
}

// fix1Disconnect closes the client and waits until the controller has
// unregistered the session (no controller pump may race the state setup).
func fix1Disconnect(t *testing.T, h *sessionHarness, client *control.Client) {
	t.Helper()
	client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := h.st.GetNode(h.nodeID)
		if err == nil && n.ControlState == "OFFLINE" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("controller never unregistered the closed session")
}

// FIX1 RED (F1-c): receipt-window corner with the agent ALREADY durably
// receipted (journal tombstone, outbox GC'd). Reconnect must not re-deliver
// the command: the row stays SEMANTIC_ACKED (a late GC is P14 sweeper scope),
// the session stays alive, and nothing is re-applied.
func TestReconnectAfterDurableAgentReceiptKeepsSessionAlive(t *testing.T) {
	h := newSessionHarness(t)
	client, err := control.NewClient(control.ClientOptions{
		Endpoint: h.srv.URL, NodeID: h.nodeID, Store: h.ls, Key: h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	epoch, session, err := h.ls.CurrentSession()
	if err != nil {
		t.Fatal(err)
	}

	// Agent: op-1 applied and durably receipted (tombstone persists).
	op := fix1DriveAgentAppliedOp1(t, h, epoch, session)
	if err := h.ls.AcceptSemanticACK(epoch, session, op); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.AcceptReceipt(epoch, session, op); err != nil {
		t.Fatal(err)
	}
	fix1Disconnect(t, h, client)

	// Controller corner state is built with no pump racing (session dead).
	fix1DriveControllerRowSemanticAcked(t, h, session)

	// Reconnect: the controller must not requeue/re-send the SEMANTIC_ACKED
	// row; the agent has nothing to resend; the session must stay ONLINE.
	var applied atomic.Int32
	client2, err := control.NewClient(control.ClientOptions{
		Endpoint: h.srv.URL, NodeID: h.nodeID, Store: h.ls, Key: h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(ctx context.Context, op control.Operation) ([]byte, error) {
			applied.Add(1)
			return []byte(`{"applied":true}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("reconnect Connect: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	online := false
	for time.Now().Before(deadline) {
		n, err := h.st.GetNode(h.nodeID)
		if err == nil && n.ControlState == "ONLINE" {
			online = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !online {
		t.Fatal("node not ONLINE after reconnect (re-delivered command killed the session?)")
	}
	row, err := h.st.ControlOutboxItemByOperation("op-1", "desired")
	if err != nil {
		t.Fatalf("op-1 row missing: %v (must stay SEMANTIC_ACKED)", err)
	}
	if row.State != "SEMANTIC_ACKED" {
		t.Fatalf("op-1 state after reconnect = %q, want SEMANTIC_ACKED (row was requeued/re-sent?)", row.State)
	}
	if got := applied.Load(); got != 0 {
		t.Fatalf("command re-delivered and applied %d times after the agent already receipted it", got)
	}
}

// FIX1 RED (F1-b): receipt-window corner WITHOUT the agent tombstone (the C2A
// receipt never arrived; the agent's outbox row is still SENT and gets
// requeued on reconnect). The result resend must heal the row end to end: the
// controller skips the FSM advance, re-binds the row to the new session,
// re-writes the idempotent C2A receipt, and the follow-up A2C receipt
// completes the GC — node ONLINE, row GONE, no command re-delivery.
func TestReconnectResultResendHealsSemanticAckedRow(t *testing.T) {
	h := newSessionHarness(t)
	client, err := control.NewClient(control.ClientOptions{
		Endpoint: h.srv.URL, NodeID: h.nodeID, Store: h.ls, Key: h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	epoch, session, err := h.ls.CurrentSession()
	if err != nil {
		t.Fatal(err)
	}

	// Agent: op-1 applied, result queued + SENT, but the C2A receipt never
	// arrived (no tombstone — the reconnect will requeue and resend it).
	fix1DriveAgentAppliedOp1(t, h, epoch, session)
	fix1Disconnect(t, h, client)

	fix1DriveControllerRowSemanticAcked(t, h, session)

	// Reconnect: the agent resends the result; the controller heals the row.
	var applied atomic.Int32
	client2, err := control.NewClient(control.ClientOptions{
		Endpoint: h.srv.URL, NodeID: h.nodeID, Store: h.ls, Key: h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(ctx context.Context, op control.Operation) ([]byte, error) {
			applied.Add(1)
			return []byte(`{"applied":true}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("reconnect Connect: %v", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	online, gone := false, false
	for time.Now().Before(deadline) {
		if n, err := h.st.GetNode(h.nodeID); err == nil && n.ControlState == "ONLINE" {
			online = true
		}
		if _, err := h.st.ControlOutboxItemByOperation("op-1", "desired"); errors.Is(err, store.ErrNotFound) {
			gone = true
		}
		if online && gone {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !online {
		t.Fatal("node not ONLINE after the result-resend heal (session killed by a stale-session receipt?)")
	}
	if !gone {
		row, err := h.st.ControlOutboxItemByOperation("op-1", "desired")
		t.Fatalf("op-1 row not GC'd by the result-resend heal: err=%v state=%s", err, row.State)
	}
	if got := applied.Load(); got != 0 {
		t.Fatalf("command re-delivered and applied %d times", got)
	}
}
