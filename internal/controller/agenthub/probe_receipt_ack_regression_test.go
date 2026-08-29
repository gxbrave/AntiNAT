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
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// overlappingProbeSink blocks the first durable RCT1 delivery so a second
// session can replay the exact message while the old handler is still inside
// the sink. The optional firstErr models a retryable manager failure at the
// same boundary.
type overlappingProbeSink struct {
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	firstErr    error
	mu          sync.Mutex
	calls       int
}

func (s *overlappingProbeSink) HandleProbeMessage(string, string, []byte) error {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	if call == 1 {
		close(s.entered)
		<-s.release
		return s.firstErr
	}
	return nil
}

func (s *overlappingProbeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *overlappingProbeSink) unblock() {
	s.releaseOnce.Do(func() { close(s.release) })
}

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
	receipts := startProbeSemanticReceiptReader(conn)
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send first probe receipt: %v", err)
	}
	if !waitFlakyProbeCalls(sink, 1) {
		t.Fatal("first probe receipt was not delivered to the sink")
	}
	state, err := st.ControlInboxState(hex.EncodeToString(messageID[:]))
	if err != nil {
		t.Fatalf("read first-delivery inbox state: %v", err)
	}
	if state != "RECEIVED" {
		t.Fatalf("first-delivery inbox state = %q, want RECEIVED", state)
	}
	select {
	case got := <-receipts:
		t.Fatalf("retryable probe sink failure emitted message_receipt before retry: operation_id=%q", got)
	case <-time.After(200 * time.Millisecond):
	}
	if err := sendA2CExact(ctx, conn, 2, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay probe receipt: %v", err)
	}
	if !waitFlakyProbeCalls(sink, 2) {
		t.Fatalf("replayed receipt was not retried after sink failure; calls=%d", sink.count())
	}
	select {
	case got := <-receipts:
		if got != operationID {
			t.Fatalf("retry semantic receipt operation_id = %q, want %q", got, operationID)
		}
	case <-time.After(time.Second):
		t.Fatal("retry semantic receipt was not emitted after successful retry")
	}
}

// exerciseOverlappingProbeReceipt drives the real hub with two overlapping
// authenticated sessions. Session A is held inside the RCT1 sink while Session
// B takes over the node and replays the exact receipt. The hub-level durable
// boundary must either suppress the duplicate after A succeeds or retry it
// after A returns a transient error.
func exerciseOverlappingProbeReceipt(t *testing.T, firstErr error, wantCalls int) {
	t.Helper()
	sink := &overlappingProbeSink{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		firstErr: firstErr,
	}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-overlap"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	first := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer first.conn.CloseNow()

	payload := []byte("overlapping-RCT1-frame")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sendA2CExact(ctx, first, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send first overlapping receipt: %v", err)
	}
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("first session did not enter probe sink")
	}

	second := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer second.conn.CloseNow()
	if err := sendA2CExact(ctx, second, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send overlapping replay: %v", err)
	}
	// Session B is blocked on the keyed delivery lock while Session A remains
	// inside the sink; a second sink invocation before release would prove the
	// lock is not protecting the durable RECEIVED boundary.
	time.Sleep(150 * time.Millisecond)
	if got := sink.count(); got != 1 {
		t.Fatalf("overlapping sink calls before release = %d, want 1", got)
	}

	sink.unblock()
	got, err := readProbeSemanticReceipt(ctx, second)
	if err != nil {
		t.Fatalf("read overlapping semantic receipt: %v", err)
	}
	if got != operationID {
		t.Fatalf("overlapping semantic receipt operation_id = %q, want %q", got, operationID)
	}
	if calls := sink.count(); calls != wantCalls {
		t.Fatalf("overlapping sink calls = %d, want %d", calls, wantCalls)
	}
	state, err := st.ControlInboxState(hex.EncodeToString(messageID[:]))
	if err != nil {
		t.Fatalf("read overlapping inbox state: %v", err)
	}
	wantState := store.ControlInboxProcessed
	if firstErr != nil {
		// The second delivery succeeds after the first retryable error.
		wantState = store.ControlInboxProcessed
	}
	if state != wantState {
		t.Fatalf("overlapping inbox state = %q, want %q", state, wantState)
	}
}

func TestOverlappingProbeReceiptReplayRunsSinkOnce(t *testing.T) {
	exerciseOverlappingProbeReceipt(t, nil, 1)
}

func TestOverlappingProbeReceiptRetryReleasesLock(t *testing.T) {
	exerciseOverlappingProbeReceipt(t, errors.New("transient overlapping sink failure"), 2)
}

// Legacy control-inbox rows created before operation_id was introduced must
// still converge through the RCT1 path. The authenticated exact payload and
// node/type binding authorize the one-way empty -> digest binding; a payload
// or node mismatch must never be used as a correlation shortcut.
func TestLegacyProbeReceiptEmptyOperationIDBindsAndConverges(t *testing.T) {
	sink := &probeSinkRecorder{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-legacy"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	payload := []byte("legacy-RCT1-frame")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	messageHex := hex.EncodeToString(messageID[:])
	rawDB := openAgentHubRawDB(t, st)
	if _, err := rawDB.Exec(`
		INSERT INTO control_inbox
			(message_id, node_id, message_type, semantic_payload, state,
			 operation_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'RECEIVED', NULL, ?, ?)`,
		messageHex, nodeID, "probe_ingress_receipt", string(payload), time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatalf("seed legacy inbox row: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send legacy probe receipt: %v", err)
	}
	got, err := readProbeSemanticReceipt(ctx, conn)
	if err != nil {
		t.Fatalf("read legacy semantic receipt: %v", err)
	}
	if got != operationID {
		t.Fatalf("legacy semantic receipt operation_id = %q, want %q", got, operationID)
	}
	item, err := st.ControlInboxItemByMessageID(messageHex)
	if err != nil {
		t.Fatalf("read bound legacy inbox row: %v", err)
	}
	if item.OperationID != operationID || item.State != store.ControlInboxProcessed || item.SemanticPayload != string(payload) {
		t.Fatalf("bound legacy inbox row = %+v, want operation=%q state=PROCESSED exact payload", item, operationID)
	}
	messages := waitSink(t, sink, 1)
	if len(messages) != 1 || messages[0].messageType != "probe_ingress_receipt" || messages[0].payload != string(payload) {
		t.Fatalf("legacy sink messages = %+v, want one exact RCT1 delivery", messages)
	}
}

// A probe_result uses the same durable inbox replay key as other probe-plane
// messages. If its first sink call fails after the inbox insert, the session
// may close, but a reconnect must retry the RECEIVED row rather than treating
// the duplicate as already consumed.
func TestProbeResultReplayAfterSinkFailureIsRetried(t *testing.T) {
	sink := &flakyProbeSink{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-rtry"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	payload := []byte(`{"probe_id":"result-retry","outcome":"REJECTED"}`)
	messageID := security.MessageID("result-retry", "probe_result")
	messageHex := hex.EncodeToString(messageID[:])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_result", payload); err != nil {
		t.Fatalf("send first probe result: %v", err)
	}
	if !waitFlakyProbeCalls(sink, 1) {
		t.Fatal("first probe result was not delivered to the sink")
	}
	state, err := st.ControlInboxState(messageHex)
	if err != nil {
		t.Fatal(err)
	}
	if state != "RECEIVED" {
		t.Fatalf("first-delivery probe result state = %q, want RECEIVED", state)
	}
	// The first sink error is fatal for the current frame loop. Close the raw
	// socket explicitly so the reconnect does not race the old read loop.
	conn.conn.CloseNow()

	conn2 := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn2.conn.CloseNow()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := sendA2CExact(ctx2, conn2, 1, messageID, "probe_result", payload); err != nil {
		t.Fatalf("replay probe result: %v", err)
	}
	if !waitFlakyProbeCalls(sink, 2) {
		t.Fatalf("replayed probe result was not retried; calls=%d", sink.count())
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state, err = st.ControlInboxState(messageHex)
		if err == nil && state == "PROCESSED" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	state, err = st.ControlInboxState(messageHex)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("replayed probe result state = %q, want PROCESSED", state)
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

func startProbeSemanticReceiptReader(conn *rawAgentConn) <-chan string {
	receipts := make(chan string, 1)
	go func() {
		for {
			_, raw, err := conn.conn.Read(context.Background())
			if err != nil {
				return
			}
			env, _, err := parseEnvelope(raw, conn.hub.ControllerPublicKey())
			if err != nil || env.Header.MessageType != "message_receipt" {
				continue
			}
			var payload struct {
				OperationID string `json:"operation_id"`
			}
			if json.Unmarshal(env.Payload, &payload) == nil {
				receipts <- payload.OperationID
			}
			return
		}
	}()
	return receipts
}

type permanentProbeSink struct {
	err error
}

func (s permanentProbeSink) HandleProbeMessage(string, string, []byte) error {
	return s.err
}

type markedPermanentProbeSink struct {
	err error
}

func (s markedPermanentProbeSink) HandleProbeMessage(string, string, []byte) error {
	return markedPermanentProbeError{err: s.err}
}

type markedPermanentProbeError struct {
	err error
}

func (e markedPermanentProbeError) Error() string               { return e.err.Error() }
func (e markedPermanentProbeError) Unwrap() error               { return e.err }
func (e markedPermanentProbeError) PermanentProbeReceipt() bool { return true }

// Authenticated but malformed probe receipts are permanent input rejection,
// not retryable sink failures. The durable inbox disposition must therefore
// leave the RECEIVED state and the Agent must receive the deterministic
// semantic ack.
func TestMalformedProbeReceiptGetsTerminalInboxDisposition(t *testing.T) {
	sink := markedPermanentProbeSink{err: protocol.ErrProbeMalformed}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-malformed"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := []byte("not-an-RCT1-frame")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send malformed probe receipt: %v", err)
	}
	state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:]))
	if state != "NACKED" {
		t.Fatalf("malformed receipt inbox state = %q, want NACKED", state)
	}
	got, err := readProbeSemanticReceipt(ctx, conn)
	if err != nil {
		t.Fatalf("read malformed-receipt semantic ack: %v", err)
	}
	if got != operationID {
		t.Fatalf("malformed-receipt ack operation_id = %q, want %q", got, operationID)
	}
}

func TestBareNotFoundProbeSinkRemainsRetryable(t *testing.T) {
	sink := permanentProbeSink{err: store.ErrNotFound}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-notfound"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := []byte("bare-not-found")
	_, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send bare-not-found receipt: %v", err)
	}
	state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:]))
	if state != "RECEIVED" {
		t.Fatalf("bare not-found inbox state = %q, want RECEIVED", state)
	}
}

func waitControlInboxState(t *testing.T, st *store.Store, messageID string) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	lastState := ""
	for time.Now().Before(deadline) {
		item, err := st.ControlInboxItemByMessageID(messageID)
		if err == nil {
			lastState = item.State
			if item.State != "RECEIVED" {
				return item.State
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	item, err := st.ControlInboxItemByMessageID(messageID)
	if err != nil {
		t.Fatalf("read inbox row %q after state %q: %v", messageID, lastState, err)
	}
	return item.State
}

// A signed receipt whose arm digest no longer maps to a bounded live operation
// is a permanent correlation rejection. It must not accumulate as RECEIVED or
// force the Agent to resend forever.
func TestUnknownProbeReceiptGetsTerminalInboxDisposition(t *testing.T) {
	sink := markedPermanentProbeSink{err: store.ErrNotFound}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-unknown"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := []byte("signed-but-unknown-rct1")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("send unknown probe receipt: %v", err)
	}
	state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:]))
	if state != "NACKED" {
		t.Fatalf("unknown receipt inbox state = %q, want NACKED", state)
	}
	got, err := readProbeSemanticReceipt(ctx, conn)
	if err != nil {
		t.Fatalf("read unknown-receipt semantic ack: %v", err)
	}
	if got != operationID {
		t.Fatalf("unknown-receipt ack operation_id = %q, want %q", got, operationID)
	}
}
