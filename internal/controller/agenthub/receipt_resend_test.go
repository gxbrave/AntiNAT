// FIX2 (P08-QUALITY F3): A2C-receipt idempotency. The controller consumed
// an agent's A2C receipt in an earlier session (outbox row GC'd), but the
// C2A receipt was lost in flight, so the agent never GC'd its own outbox
// row and resends the SAME receipt (deterministic message id, protocol.md
// §3.5) on reconnect. handleAgentReceipt must honor the RecordControlInbox
// duplicate flag and tolerate the failed row match — the row is gone by
// design — instead of failing the session closed and repeating on every
// reconnect (control channel dead, agent row leaked).
package agenthub_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// sendA2CWithID writes a signed A2C envelope with an explicit deterministic
// message id (the receipt resend must re-use the id derived from the
// operation, not a placeholder).
func (c *rawAgentConn) sendA2CWithID(ctx context.Context, seq uint64, msgType string, payload []byte, msgID [16]byte) error {
	instance := c.hub.ControllerInstanceID()
	var node [16]byte
	copy(node[:], c.nodeID)
	header := protocol.ProtectedHeader{
		ProtocolDomain:       protocol.ProtocolDomain,
		ControllerInstanceID: instance,
		NodeID:               node,
		ControllerKeyID:      c.hub.ControllerKeyID(),
		AgentCredentialVer:   1,
		ConnectionEpoch:      c.epoch,
		SessionID:            c.sess,
		Direction:            protocol.DirectionA2C,
		Sequence:             seq,
		MessageID:            msgID,
		MessageType:          msgType,
		SchemaVersion:        1,
	}
	frame, err := protocol.BuildEnvelope(c.key.PrivateKey(), header, payload)
	if err != nil {
		return err
	}
	return c.conn.Write(ctx, websocket.MessageBinary, frame)
}

// expectSilentSession asserts the session stays alive: a killed session is
// closed by the hub within milliseconds of a rejected frame, so any read
// error inside the silence window is a kill. An alive session with no C2A
// traffic stays silent until the caller cancels ctx (a deadline ctx would
// self-close the client conn via coder/websocket's timeoutLoop, so the read
// must be cancelable, not time-bounded).
func expectSilentSession(t *testing.T, conn *rawAgentConn, ctx context.Context, window time.Duration) {
	t.Helper()
	readErr := make(chan error, 1)
	go func() {
		_, _, err := conn.conn.Read(ctx)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		t.Fatalf("session killed by consumed-receipt resend: %v", err)
	case <-time.After(window):
		// Still silent: the resend was tolerated idempotently.
	}
}

// FIX2 F3: a reconnect resend of an already-consumed A2C receipt must be
// tolerated idempotently. The controller corner state (the receipt durably
// recorded in control_inbox, the outbox row GC'd after consumption) is
// driven directly BEFORE the reconnect session dials, mirroring the FIX1
// deterministic corner tests: no live session exists during the setup, so no
// hub goroutine (audit writes, outbox pump) can race the store driving. The
// agent-side operation id is the hex command message id (handleAgentResult
// candidate A), so the A2C receipt references agentOp and its own message id
// is security.MessageID(agentOp, "message_receipt"). The resend must not
// fail the row match and kill the session.
func TestReconnectResendOfConsumedReceiptKeepsSessionAlive(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)

	// The earlier session (whose C2A receipt was lost) processed op-1 and
	// its A2C receipt was consumed: row advanced through the legal FSM
	// (bound to that session id), receipt recorded, then GC'd.
	firstSession := "f2-consumed-session"
	cmdID := security.MessageID("op-1", "desired")
	agentOp := hex.EncodeToString(cmdID[:])
	receiptPayload := fmt.Sprintf(`{"operation_id":%q}`, agentOp)
	receiptID := security.MessageID(agentOp, "message_receipt")
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-1", MessageType: "desired", NodeID: nodeID,
		SemanticPayload: `{"node_id":"node-a","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ClaimControlOutboxOperation("op-1", "desired", firstSession); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkControlOutboxSent("op-1", "desired", firstSession); err != nil {
		t.Fatal(err)
	}
	if err := st.AcceptControlSemanticACK("op-1", "desired", firstSession); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordControlInbox(store.ControlInboxItem{
		MessageID: hex.EncodeToString(receiptID[:]), NodeID: nodeID,
		MessageType: "message_receipt", SemanticPayload: receiptPayload,
		State: "RECEIVED",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AcceptControlReceipt("op-1", "desired", firstSession); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ControlOutboxItemByOperation("op-1", "desired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("op-1 outbox row not GC'd: err=%v", err)
	}

	// Reconnect: the agent still holds its un-receipted outbox row (the C2A
	// receipt never arrived) and resends the same A2C receipt — same message
	// id + payload the controller already recorded, so RecordControlInbox
	// reports the cached duplicate and no outbox row exists to match.
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := conn.sendA2CWithID(ctx, 1, "message_receipt", []byte(receiptPayload), receiptID); err != nil {
		t.Fatal(err)
	}
	// The resend must be tolerated: the session stays silent and alive for
	// the observation window (a rejected frame closes it within ms).
	expectSilentSession(t, conn, ctx, 1500*time.Millisecond)
	// Liveness: the node stays ONLINE with the session retained.
	n, err := st.GetNode(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if n.ControlState != "ONLINE" {
		t.Fatalf("node control state = %q, want ONLINE (session survived)", n.ControlState)
	}
}
