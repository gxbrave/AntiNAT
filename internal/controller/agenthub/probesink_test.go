package agenthub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// parseEnvelope parses a C2A envelope with the agent key (test helper).
func parseEnvelope(raw []byte, agentPub ed25519.PublicKey) (protocol.Envelope, protocol.Stage, error) {
	return protocol.ParseEnvelope(raw, agentPub)
}

// msgID derives the deterministic message id (mirrors security.MessageID).
func msgID(operationID, messageType string) [16]byte {
	h := sha256.Sum256([]byte("antinat-msgid-v1\x00" + operationID + "\x00" + messageType))
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

// sendA2CExact writes a signed A2C envelope with an explicit message id.
func sendA2CExact(ctx context.Context, c *rawAgentConn, seq uint64, messageID [16]byte, msgType string, payload []byte) error {
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
		MessageID:            messageID,
		MessageType:          msgType,
		SchemaVersion:        1,
	}
	frame, err := protocol.BuildEnvelope(c.key.PrivateKey(), header, payload)
	if err != nil {
		return err
	}
	return c.conn.Write(ctx, websocket.MessageBinary, frame)
}

// probeSinkRecorder implements agenthub.ProbeSink for tests.
type probeSinkRecorder struct {
	mu       sync.Mutex
	messages []probeMessage
}

type probeMessage struct {
	nodeID      string
	messageType string
	payload     string
}

func (r *probeSinkRecorder) HandleProbeMessage(nodeID, messageType string, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, probeMessage{nodeID: nodeID, messageType: messageType, payload: string(payload)})
	return nil
}

func (r *probeSinkRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.messages)
}

func (r *probeSinkRecorder) all() []probeMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]probeMessage(nil), r.messages...)
	return out
}

// waitSink polls until the sink recorded at least n messages or the deadline
// passes, returning the recorded messages.
func waitSink(t *testing.T, r *probeSinkRecorder, n int) []probeMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.count() >= n {
			return r.all()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return r.all()
}

// newSinkHub builds a hub with a probe sink plus an httptest server.
func newSinkHub(t *testing.T, sink agenthub.ProbeSink) (*agenthub.Hub, *store.Store, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := agenthub.NewHub(agenthub.Config{
		Store:      st,
		Keyring:    kr,
		Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock:      time.Now,
		ProbeSink:  sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)
	return hub, st, srv.URL
}

// TestProbeSinkReceivesProbePlaneMessages verifies the hub forwards durable
// probe-plane A2C messages (probe_ingress_receipt with RCT1 bytes and
// probe_result) to the configured sink without killing the session, and that
// a probe_armed result correlated to a probe_arm outbox row also reaches the
// sink. This is the P10 declared extension: the probe manager consumes the
// control channel through this interface.
func TestProbeSinkReceivesProbePlaneMessages(t *testing.T) {
	sink := &probeSinkRecorder{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)

	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Agent-initiated probe_ingress_receipt (RCT1 frame bytes).
	if err := sendA2CExact(ctx, conn, 1, msgID("probe-1", "probe_ingress_receipt"), "probe_ingress_receipt", []byte("RCT1-frame-bytes")); err != nil {
		t.Fatalf("send probe_ingress_receipt: %v", err)
	}
	// Agent-initiated probe_result.
	if err := sendA2CExact(ctx, conn, 2, msgID("probe-1", "probe_result"), "probe_result", []byte(`{"probe_id":"p1","outcome":"REJECTED"}`)); err != nil {
		t.Fatalf("send probe_result: %v", err)
	}

	// Controller enqueues a probe_arm command; the agent answers with a
	// probe_armed (RDY1) result correlated to the outbox row; the sink must
	// receive it too.
	armPayload := `{"arm":"ARM1-canonical-bytes"}`
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID:     "probe-1",
		MessageType:     "probe_arm",
		NodeID:          nodeID,
		SemanticPayload: armPayload,
		State:           "PENDING",
	}); err != nil {
		t.Fatalf("enqueue probe_arm: %v", err)
	}

	// The hub pump sends the arm C2A; the raw agent must answer with a
	// dedicated probe_armed A2C message (frozen type) carrying the RDY1
	// frame bytes and a deterministic message id for resend dedup.
	_, rawCmd, err := conn.conn.Read(ctx)
	if err != nil {
		t.Fatalf("read probe_arm command: %v", err)
	}
	cmdEnv, _, err := protocol.ParseEnvelope(rawCmd, conn.hub.ControllerPublicKey())
	if err != nil {
		t.Fatalf("parse arm command: %v", err)
	}
	if cmdEnv.Header.MessageType != "probe_arm" {
		t.Fatalf("command type = %q, want probe_arm", cmdEnv.Header.MessageType)
	}
	armedMsgID := msgID("probe-1", "probe_armed")
	if err := sendA2CExact(ctx, conn, 3, armedMsgID, "probe_armed", []byte("RDY1-frame-bytes")); err != nil {
		t.Fatalf("send probe_armed: %v", err)
	}

	got := waitSink(t, sink, 3)
	byType := map[string]string{}
	for _, m := range got {
		if m.nodeID != nodeID {
			t.Fatalf("sink message for wrong node %q", m.nodeID)
		}
		byType[m.messageType] = m.payload
	}
	if _, ok := byType["probe_ingress_receipt"]; !ok {
		t.Fatalf("sink missing probe_ingress_receipt: %+v", got)
	}
	if _, ok := byType["probe_result"]; !ok {
		t.Fatalf("sink missing probe_result: %+v", got)
	}
	if _, ok := byType["probe_armed"]; !ok {
		t.Fatalf("sink missing probe_armed: %+v", got)
	}

	// The session must still be alive after probe-plane traffic.
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session died after probe messages: %v", err)
	}
}

// TestProbeSinkDedupsReplayedReceipt verifies a replayed probe_ingress_receipt
// (same message id + payload) is deduped durably and not double-forwarded,
// and does not kill the session.
func TestProbeSinkDedupsReplayedReceipt(t *testing.T) {
	sink := &probeSinkRecorder{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)

	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Deterministic message id for the same probe receipt (resend dedup).
	receiptMsgID := msgID("probe-1", "probe_ingress_receipt")
	if err := sendA2CExact(ctx, conn, 1, receiptMsgID, "probe_ingress_receipt", []byte("RCT1-frame")); err != nil {
		t.Fatalf("send receipt: %v", err)
	}
	// Replay the exact same envelope id + payload (sequence advances).
	if err := sendA2CExact(ctx, conn, 2, receiptMsgID, "probe_ingress_receipt", []byte("RCT1-frame")); err != nil {
		t.Fatalf("replay receipt: %v", err)
	}

	got := waitSink(t, sink, 1)
	count := 0
	for _, m := range got {
		if m.messageType == "probe_ingress_receipt" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("replayed receipt forwarded %d times, want 1 (dedup): %+v", count, got)
	}
	if err := conn.sendA2C(ctx, 3, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session died after replayed receipt: %v", err)
	}
}
