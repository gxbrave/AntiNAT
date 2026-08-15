package agenthub_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// flakyProbeSink models a controller restart or manager failure after the
// durable inbox write but before the semantic probe receipt is acknowledged.
// The first delivery fails; the second delivery must be retried after the
// agent reconnects/resends the same deterministic message id.
type flakyProbeSink struct {
	mu    sync.Mutex
	calls int
}

func (s *flakyProbeSink) HandleProbeMessage(string, string, []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 {
		return errors.New("transient probe manager failure")
	}
	return nil
}

func (s *flakyProbeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func actualProbeMessageID(payload []byte, messageType string) (string, [16]byte) {
	sum := sha256.Sum256(payload)
	operationID := hex.EncodeToString(sum[:])
	return operationID, security.MessageID(operationID, messageType)
}

func readProbeSemanticReceipt(ctx context.Context, conn *rawAgentConn) (string, error) {
	for {
		_, raw, err := conn.conn.Read(ctx)
		if err != nil {
			return "", err
		}
		env, _, err := parseEnvelope(raw, conn.hub.ControllerPublicKey())
		if err != nil {
			return "", err
		}
		if env.Header.MessageType != "message_receipt" {
			continue
		}
		var payload struct {
			OperationID string `json:"operation_id"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return "", err
		}
		return payload.OperationID, nil
	}
}

// Every accepted probe_ingress_receipt must receive the same durable semantic
// Controller acknowledgment used by the Agent's receipt journal. A transport
// write alone is not enough to let the Agent delete its RCT1 tombstone.
func TestProbeReceiptGetsSemanticControllerAck(t *testing.T) {
	sink := &probeSinkRecorder{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-receipt"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := []byte("RCT1-frame-for-ack")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send probe receipt: %v", err)
	}
	got, err := readProbeSemanticReceipt(ctx, conn)
	if err != nil {
		t.Fatalf("read semantic receipt: %v", err)
	}
	if got != operationID {
		t.Fatalf("semantic receipt operation_id = %q, want %q", got, operationID)
	}
}

// A duplicate probe receipt is normally deduplicated. If its first delivery
// failed after inbox persistence, however, the duplicate is the Agent's
// reconnect/retry signal and must be forwarded again rather than being lost
// behind the durable duplicate key.
func TestProbeReceiptReplayAfterSinkFailureIsRetried(t *testing.T) {
	sink := &flakyProbeSink{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-retry"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := []byte("RCT1-frame-for-retry")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send first probe receipt: %v", err)
	}
	if !waitFlakyProbeCalls(sink, 1) {
		t.Fatal("first probe receipt was not delivered to the sink")
	}
	if err := sendA2CExact(ctx, conn, 2, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay probe receipt: %v", err)
	}
	if !waitFlakyProbeCalls(sink, 2) {
		t.Fatalf("replayed receipt was not retried after sink failure; calls=%d", sink.count())
	}
	got, err := readProbeSemanticReceipt(ctx, conn)
	if err != nil {
		t.Fatalf("read retry semantic receipt: %v", err)
	}
	if got != operationID {
		t.Fatalf("retry semantic receipt operation_id = %q, want %q", got, operationID)
	}
}

func waitFlakyProbeCalls(sink *flakyProbeSink, want int) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if sink.count() >= want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return sink.count() >= want
}
