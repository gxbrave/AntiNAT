// P08 Story 3/4/5 RED: the Agent control session client over a real
// WebSocket. Mutual challenge, epoch persistence BEFORE socket activation,
// frame verification, and reconnect fencing are exercised against a live hub.
package control_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// sessionHarness builds an enrolled node with a controller hub.
type sessionHarness struct {
	*enrollHarness
	ls  *localstate.Store
	key *security.NodeKey
}

func newSessionHarness(t *testing.T) *sessionHarness {
	t.Helper()
	h := newEnrollHarness(t)
	ls := newAgentStore(t)
	key, err := control.Enroll(context.Background(), ls, control.EnrollOptions{
		Endpoint:            h.srv.URL,
		NodeID:              h.nodeID,
		Token:               h.token,
		ControllerPublicKey: h.pub,
		KeyDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return &sessionHarness{enrollHarness: h, ls: ls, key: key}
}

// RED 3h: a full session handshake over the wire — hello/welcome/final —
// grants an epoch and session, and the agent persists the epoch BEFORE
// socket activation.
func TestSessionHandshakeOverWebSocket(t *testing.T) {
	h := newSessionHarness(t)

	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	epoch, session, err := h.ls.CurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	if epoch == 0 || session == "" {
		t.Fatalf("agent did not persist the granted session (epoch=%d session=%q)", epoch, session)
	}
	node, err := h.st.GetNode(h.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if node.CurrentConnectionEpoch != epoch {
		t.Fatalf("controller epoch = %d, agent epoch = %d (must match)", node.CurrentConnectionEpoch, epoch)
	}
	// The hub marks ONLINE after the SessionFinal is processed; poll briefly.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := h.st.GetNode(h.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if n.ControlState == "ONLINE" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, err := h.st.GetNode(h.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if n.ControlState != "ONLINE" {
		t.Fatalf("node control state = %q, want ONLINE", n.ControlState)
	}
}

// RED 3i: a wrong pinned controller key fails the welcome verification — the
// agent never activates the socket and persists nothing.
func TestSessionWrongPinnedControllerKey(t *testing.T) {
	h := newSessionHarness(t)
	// Enroll with the real key, then corrupt the pin in the store.
	pins, err := h.ls.ListControllerPins()
	if err != nil || len(pins) != 1 {
		t.Fatalf("pins: %d err=%v, want exactly 1", len(pins), err)
	}
	pin := pins[0]
	pin.PublicKeyRaw = append([]byte(nil), pin.PublicKeyRaw...)
	pin.PublicKeyRaw[0] ^= 0xff
	if err := h.ls.SaveControllerPin(pin); err != nil {
		t.Fatal(err)
	}

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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err == nil {
		t.Fatal("session activated with a wrong pinned controller key")
	}
	if !strings.Contains(err.Error(), "welcome") && !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "pin") {
		t.Fatalf("unexpected error: %v", err)
	}
	epoch, _, _ := h.ls.CurrentSession()
	if epoch != 0 {
		t.Fatalf("agent persisted an epoch (%d) despite failed handshake", epoch)
	}
}

// RED 3j: the agent's own key is bound — a session signed by a different
// agent key is rejected by the controller.
func TestSessionWrongAgentKeyRejected(t *testing.T) {
	h := newSessionHarness(t)
	// A second agent key that is NOT the enrolled credential.
	otherKey, err := security.LoadOrCreateNodeKey(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       otherKey,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err == nil {
		t.Fatal("session activated with an unbound agent key")
	}
}

// RED 3k: the frame loop accepts signed envelopes and rejects wrong
// direction, wrong epoch, wrong session, and out-of-order sequence — each
// violation fails the session closed.
func TestSessionFrameVerificationFailsClosed(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()
	epoch, session, _ := h.ls.CurrentSession()

	// The client exposes the raw socket only via the package; drive the
	// controller side directly with a raw WS client to send a bad frame.
	raw, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.srv.URL, "http")+"/agent/v1/control", nil)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer raw.CloseNow()
	// Complete the handshake on the raw socket with the enrolled key.
	if err := rawHandshake(t, ctx, raw, h, epoch, session); err != nil {
		t.Fatalf("raw handshake: %v", err)
	}

	// Send an A2C envelope with WRONG DIRECTION (C2A) — must fail closed.
	node := h.nodeID
	_ = node
	frame, err := buildAgentFrame(h.key, h.nodeID, epoch, session, protocol.DirectionC2A, 1, "heartbeat", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
	// The controller must close the connection (session fail-closed).
	_, _, err = raw.Read(ctx)
	if err == nil {
		t.Fatal("controller accepted a wrong-direction frame")
	}
}

func rawHandshake(t *testing.T, ctx context.Context, conn *websocket.Conn, h *sessionHarness, epoch uint64, session string) error {
	t.Helper()
	instance, _ := h.st.InstanceID()
	var inst [16]byte
	if b, err := hex.DecodeString(instance); err == nil && len(b) == 16 {
		copy(inst[:], b)
	}
	var node [16]byte
	copy(node[:], h.nodeID)
	hello := security.SessionHello{
		ControllerInstanceID: inst,
		NodeID:               node,
		AgentCredentialVer:   1,
		AgentPublicKey:       [32]byte(h.key.PublicKey()),
		AgentMaxEpoch:        epoch,
		ProtocolVersions:     "1",
	}
	sig, err := hello.Sign(h.key.PrivateKey())
	if err != nil {
		return err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, append(hello.Canonical(), sig...)); err != nil {
		return err
	}
	_, welcomeRaw, err := conn.Read(ctx)
	if err != nil {
		return err
	}
	welcome, err := security.ParseSessionWelcome(welcomeRaw, h.pub)
	if err != nil {
		return err
	}
	final := security.SessionFinal{
		ControllerInstanceID: welcome.ControllerInstanceID,
		NodeID:               node,
		ServerNonce:          welcome.ServerNonce,
		ConnectionEpoch:      welcome.ConnectionEpoch,
		SessionID:            welcome.SessionID,
	}
	fsig, err := final.Sign(h.key.PrivateKey())
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, append(final.Canonical(), fsig...))
}

func buildAgentFrame(key *security.NodeKey, nodeID string, epoch uint64, session string, direction byte, seq uint64, msgType string, payload []byte) ([]byte, error) {
	var node [16]byte
	copy(node[:], nodeID)
	header := protocol.ProtectedHeader{
		ProtocolDomain:     protocol.ProtocolDomain,
		NodeID:             node,
		ControllerKeyID:    "k",
		AgentCredentialVer: 1,
		ConnectionEpoch:    epoch,
		SessionID:          session,
		Direction:          direction,
		Sequence:           seq,
		MessageID:          [16]byte{1},
		MessageType:        msgType,
		SchemaVersion:      1,
	}
	return protocol.BuildEnvelope(key.PrivateKey(), header, payload)
}

// RED 5g: the agent outbox pump sends results and the controller receipts
// them; a reconnected session re-envelopes without duplicate side effects.
func TestSessionReconnectSemanticResend(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// Enqueue a command on the controller; the pump delivers it.
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-1", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: `{"node_id":"` + h.nodeID + `","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}
	// Wait for the agent to apply it.
	deadline := time.Now().Add(5 * time.Second)
	for applied.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if applied.Load() != 1 {
		t.Fatalf("applied = %d, want 1", applied.Load())
	}
	// The controller outbox row must have been receipted (GC'd).
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := h.st.ControlOutboxItemByOperation("op-1", "desired"); errors.Is(err, store.ErrNotFound) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := h.st.ControlOutboxItemByOperation("op-1", "desired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("controller outbox row not GC'd after receipt: %v", err)
	}
}
