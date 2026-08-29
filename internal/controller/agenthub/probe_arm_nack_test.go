package agenthub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

type recordingProbeSink struct {
	manager  *probe.Manager
	mu       sync.Mutex
	types    []string
	payloads [][]byte
}

func (s *recordingProbeSink) HandleProbeMessage(nodeID, messageType string, payload []byte) error {
	s.mu.Lock()
	s.types = append(s.types, messageType)
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	s.mu.Unlock()
	return s.manager.HandleProbeMessage(nodeID, messageType, payload)
}

func (s *recordingProbeSink) snapshot() ([]string, [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	types := append([]string(nil), s.types...)
	payloads := make([][]byte, len(s.payloads))
	for i := range s.payloads {
		payloads[i] = append([]byte(nil), s.payloads[i]...)
	}
	return types, payloads
}

// TestProbeArmRecoveryNACKUsesProbeResultPath proves that the Agent's
// recovered journal NACK on the existing operation_complete wire is translated
// into a probe_result/REJECTED sink call. The JSON NACK must never be parsed as
// RDY1, must not start an independent provider request, and must still complete
// the normal Controller outbox receipt lifecycle.
func TestProbeArmApplicationNACKUsesProbeResultPath(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "node-nack-route"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateForward(store.Forward{
		ID: "nack-route-forward", NodeID: nodeID, Name: "nack-route-forward",
		Protocol: "tcp", CurrentActivationID: "nack-route-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetForwardRuntimeStatus("nack-route-forward", "nack-route-activation", 1, integrationRuntimeSnapshot); err != nil {
		t.Fatal(err)
	}

	providerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := &gatedProvider{first: make(chan struct{}), release: make(chan struct{})}
	providerSrv := httptest.NewServer(http.HandlerFunc(provider.handler))
	t.Cleanup(providerSrv.Close)
	if _, err := st.CreateProbeProvider(store.ProbeProvider{
		ID: "nack-route-provider", Name: "nack-route-provider",
		PublicKey: hex.EncodeToString(providerPub), EgressIP: "198.51.100.9",
		Endpoint: providerSrv.URL, Enabled: true, IndependentVantage: true,
	}); err != nil {
		t.Fatal(err)
	}

	var hub *agenthub.Hub
	mgr, err := probe.NewManager(probe.ManagerConfig{
		Store: st, Keyring: kr, Clock: time.Now, HTTPClient: providerSrv.Client(),
		NodePublicKey: func(id string) (ed25519.PublicKey, bool) {
			if hub == nil || id != nodeID {
				return nil, false
			}
			return hub.AgentPublicKey(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingProbeSink{manager: mgr}
	hub, err = agenthub.NewHub(agenthub.Config{
		Store: st, Keyring: kr, Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock: time.Now, ProbeSink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	hubSrv := httptest.NewServer(hub.Handler())
	t.Cleanup(hubSrv.Close)

	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, hubSrv.URL, nodeID, key)
	defer conn.conn.CloseNow()

	op, err := mgr.Arm(context.Background(), nodeID, "nack-route-forward", "nack-route-activation", "198.51.100.7:8080")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = readC2AType(t, conn, ctx, "probe_arm")

	commandID := security.MessageID(op.ID, "probe_arm")
	agentOperationID := hex.EncodeToString(commandID[:])
	resultID := security.MessageID(agentOperationID, "operation_complete")
	resultPayload := []byte(`{"status":"nacked","reason":"recovered APPLYING operation after restart","recovered":true}`)
	if err := sendA2CExact(ctx, conn, 1, resultID, "operation_complete", resultPayload); err != nil {
		t.Fatalf("send application NACK: %v", err)
	}

	resultMessageID := hex.EncodeToString(resultID[:])
	item, err := waitControlInboxItem(t, st, resultMessageID)
	if err != nil {
		t.Fatal(err)
	}
	// The sink may durably reject the probe before the transport projection
	// reaches PROCESSED. Wait for the operation outcome and the inbox state;
	// these are separate durable boundaries and may be observed in either order
	// under -race scheduling.
	waitProbeOperationStatus(t, st, op.ID, string(protocol.OutcomeRejected))
	if state := waitControlInboxState(t, st, resultMessageID); state != store.ControlInboxProcessed {
		t.Fatalf("NACK result inbox state = %q, want PROCESSED", state)
	}
	item, err = st.ControlInboxItemByMessageID(resultMessageID)
	if err != nil {
		t.Fatal(err)
	}
	if item.OperationID != agentOperationID || item.SemanticPayload != string(resultPayload) {
		t.Fatalf("NACK result inbox = %+v, want exact result binding", item)
	}
	waitProbeOperationStatus(t, st, op.ID, string(protocol.OutcomeRejected))
	if got := provider.count(); got != 0 {
		t.Fatalf("provider requests after application NACK = %d, want 0", got)
	}

	types, payloads := sink.snapshot()
	if len(types) != 1 || types[0] != "probe_result" {
		t.Fatalf("sink calls = %v, want exactly [probe_result]", types)
	}
	var translated struct {
		ProbeID string `json:"probe_id"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(payloads[0], &translated); err != nil {
		t.Fatalf("decode translated probe result: %v", err)
	}
	if translated.ProbeID != op.ID || translated.Outcome != string(protocol.OutcomeRejected) {
		t.Fatalf("translated probe result = %+v, want probe %q REJECTED", translated, op.ID)
	}

	receipt := readC2AType(t, conn, ctx, "message_receipt")
	var receiptPayload struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(receipt.Payload, &receiptPayload); err != nil {
		t.Fatal(err)
	}
	if receiptPayload.OperationID != agentOperationID {
		t.Fatalf("semantic result receipt operation_id = %q, want %q", receiptPayload.OperationID, agentOperationID)
	}
	row, err := st.ControlOutboxItemByOperation(op.ID, "probe_arm")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "SEMANTIC_ACKED" {
		t.Fatalf("probe_arm outbox state = %q, want SEMANTIC_ACKED", row.State)
	}

	controllerReceiptID := security.MessageID(agentOperationID, "message_receipt")
	if err := sendA2CExact(ctx, conn, 2, controllerReceiptID, "message_receipt", []byte(`{"operation_id":"`+agentOperationID+`"}`)); err != nil {
		t.Fatalf("send controller receipt: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := st.ControlOutboxItemByOperation(op.ID, "probe_arm"); errors.Is(err, store.ErrNotFound) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := st.ControlOutboxItemByOperation(op.ID, "probe_arm"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("probe_arm outbox not GC'd after receipt: %v", err)
	}
	if got, err := st.ControlInboxState(hex.EncodeToString(controllerReceiptID[:])); err != nil || got != store.ControlInboxProcessed {
		t.Fatalf("controller receipt inbox = %q err=%v, want PROCESSED", got, err)
	}
	if err := conn.sendA2C(ctx, 3, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session died after application NACK lifecycle: %v", err)
	}
}

type countingPermanentProbeSink struct {
	mu    sync.Mutex
	calls int
}

func (s *countingPermanentProbeSink) HandleProbeMessage(string, string, []byte) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return markedPermanentProbeError{err: protocol.ErrProbeMalformed}
}

func (s *countingPermanentProbeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestNACKedProbeReceiptReplayDoesNotReinvokeSink proves that a terminal
// transport rejection is a durable replay tombstone. An exact duplicate may
// receive the same deterministic acknowledgement, but it must not call the
// sink again or create/advance any outbox work.
func TestNACKedProbeReceiptReplayDoesNotReinvokeSink(t *testing.T) {
	sink := &countingPermanentProbeSink{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-nack-rply"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	payload := []byte("permanently malformed receipt")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	messageHex := hex.EncodeToString(messageID[:])
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send first malformed receipt: %v", err)
	}
	if got, err := readProbeSemanticReceipt(ctx, conn); err != nil || got != operationID {
		t.Fatalf("first rejection receipt = %q err=%v, want %q", got, err, operationID)
	}
	if got := sink.count(); got != 1 {
		t.Fatalf("first rejection sink calls = %d, want 1", got)
	}
	if state, err := st.ControlInboxState(messageHex); err != nil || state != store.ControlInboxNacked {
		t.Fatalf("first rejection inbox = %q err=%v, want NACKED", state, err)
	}

	if err := sendA2CExact(ctx, conn, 2, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay malformed receipt: %v", err)
	}
	if got, err := readProbeSemanticReceipt(ctx, conn); err != nil || got != operationID {
		t.Fatalf("replay rejection receipt = %q err=%v, want %q", got, err, operationID)
	}
	if got := sink.count(); got != 1 {
		t.Fatalf("replayed rejection sink calls = %d, want no reinvocation", got)
	}
	if state, err := st.ControlInboxState(messageHex); err != nil || state != store.ControlInboxNacked {
		t.Fatalf("replayed rejection inbox = %q err=%v, want NACKED", state, err)
	}
	if err := conn.sendA2C(ctx, 3, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session died after NACKED replay: %v", err)
	}
}
