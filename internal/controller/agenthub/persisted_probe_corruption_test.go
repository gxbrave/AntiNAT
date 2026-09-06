package agenthub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func TestPersistedProbeCorruptionRemainsRetryableAndConvergesAfterRepair(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "node-corrupt"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	providerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProbeProvider(store.ProbeProvider{
		ID: "corrupt-provider", Name: "corrupt-provider",
		PublicKey: hex.EncodeToString(providerPub), EgressIP: "198.51.100.9",
		Endpoint: "https://provider.invalid", Enabled: true, IndependentVantage: true,
	}); err != nil {
		t.Fatal(err)
	}
	var nodePub ed25519.PublicKey
	mgr, err := probe.NewManager(probe.ManagerConfig{
		Store: st, Keyring: kr, Clock: time.Now,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			return nodePub, len(nodePub) != 0
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	arm := testReceiptArm(9, "corrupt-provider")
	challenge := [32]byte{0x33}
	op, err := st.CreateProbeOperation(store.ProbeOperation{
		ID: "corrupt-operation", NodeID: nodeID, ProviderID: "corrupt-provider",
		Status: "ARMED", Endpoint: arm.Endpoint, ArmHex: hex.EncodeToString(arm.Canonical()),
		ChallengeHash: hex.EncodeToString(challenge[:]), TTLMS: arm.TTLMS,
		ExpiryOpaque: hex.EncodeToString(arm.ExpiryOpaque[:]), ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	hub, err := agenthub.NewHub(agenthub.Config{
		Store: st, Keyring: kr, Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock: time.Now, ProbeSink: mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)
	key := enrollRaw(t, hub, st, nodeID)
	nodePub = key.PublicKey()
	conn := dialRawAgent(t, hub, st, srv.URL, nodeID, key)
	defer conn.conn.CloseNow()

	payload := signedReceipt(key, arm, challenge)
	digest := sha256.Sum256(payload)
	operationID := hex.EncodeToString(digest[:])
	messageID := security.MessageID(operationID, "probe_ingress_receipt")
	rawDB := openAgentHubRawDB(t, st)
	if _, err := rawDB.Exec(`UPDATE probe_operations SET arm_hex = ? WHERE id = ?`, "not-an-arm", op.ID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatal(err)
	}
	item, err := waitControlInboxItem(t, st, hex.EncodeToString(messageID[:]))
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "RECEIVED" || item.SemanticPayload != string(payload) {
		t.Fatalf("inbox item = %+v, want RECEIVED with exact receipt bytes", item)
	}
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after corruption: %v", err)
	}

	if _, err := rawDB.Exec(`UPDATE probe_operations SET arm_hex = ? WHERE id = ?`, hex.EncodeToString(arm.Canonical()), op.ID); err != nil {
		t.Fatal(err)
	}
	if err := sendA2CExact(ctx, conn, 3, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay repaired receipt: %v", err)
	}
	got, err := readProbeSemanticReceipt(ctx, conn)
	if err != nil {
		t.Fatalf("read repaired semantic receipt: %v", err)
	}
	if got != operationID {
		t.Fatalf("receipt operation id = %q, want %q", got, operationID)
	}
	item, err = waitControlInboxItem(t, st, hex.EncodeToString(messageID[:]))
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "PROCESSED" || item.SemanticPayload != string(payload) {
		t.Fatalf("replayed inbox item = %+v, want PROCESSED with exact receipt bytes", item)
	}
	results, err := st.ListProbeResults(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Kind != "rct1" || results[0].PayloadHex != hex.EncodeToString(payload) {
		t.Fatalf("probe results after repair = %+v, want one exact rct1", results)
	}
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after repair: %v", err)
	}
}

func TestPersistedProbeChallengeCorruptionRemainsReceivedThroughRealAgentHub(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "node-challenge"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	var nodePub ed25519.PublicKey
	mgr, err := probe.NewManager(probe.ManagerConfig{
		Store: st, Keyring: kr, Clock: time.Now,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			return nodePub, len(nodePub) != 0
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	arm := testReceiptArm(7, "challenge-provider")
	if _, err := st.CreateProbeOperation(store.ProbeOperation{
		ID: "challenge-corrupt-operation", NodeID: nodeID, ProviderID: "challenge-provider",
		Status: "ARMED", Endpoint: arm.Endpoint, ArmHex: hex.EncodeToString(arm.Canonical()),
		ChallengeHash: "not-a-sha256-hash", TTLMS: arm.TTLMS,
		ExpiryOpaque: hex.EncodeToString(arm.ExpiryOpaque[:]), ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	hub, err := agenthub.NewHub(agenthub.Config{
		Store: st, Keyring: kr, Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock: time.Now, ProbeSink: mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)
	key := enrollRaw(t, hub, st, nodeID)
	nodePub = key.PublicKey()
	conn := dialRawAgent(t, hub, st, srv.URL, nodeID, key)
	defer conn.conn.CloseNow()

	challenge := [32]byte{0x55}
	payload := signedReceipt(key, arm, challenge)
	digest := sha256.Sum256(payload)
	operationID := hex.EncodeToString(digest[:])
	messageID := security.MessageID(operationID, "probe_ingress_receipt")
	ctx := context.Background()
	events, stopReader := startProbeC2AReader(conn)
	defer stopReader()
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatal(err)
	}
	state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:]))
	if state != "RECEIVED" {
		t.Fatalf("challenge-corruption inbox state = %q, want RECEIVED", state)
	}
	assertNoProbeSemanticAck(t, events, 150*time.Millisecond)
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after challenge corruption: %v", err)
	}

	rawDB := openAgentHubRawDB(t, st)
	if _, err := rawDB.Exec(`UPDATE probe_operations SET challenge_hash = ? WHERE id = ?`, hex.EncodeToString(challenge[:]), "challenge-corrupt-operation"); err != nil {
		t.Fatal(err)
	}
	if err := sendA2CExact(ctx, conn, 3, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay repaired challenge receipt: %v", err)
	}
	if got := waitProbeSemanticAck(t, events, operationID); got != operationID {
		t.Fatalf("repaired challenge receipt operation id = %q, want %q", got, operationID)
	}
	if state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:])); state != "PROCESSED" {
		t.Fatalf("repaired challenge inbox state = %q, want PROCESSED", state)
	}
	results, err := st.ListProbeResults("challenge-corrupt-operation")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Kind != "rct1" || results[0].PayloadHex != hex.EncodeToString(payload) {
		t.Fatalf("challenge results after repair = %+v, want one exact rct1", results)
	}
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after challenge repair: %v", err)
	}
}

func TestProbeLookupBudgetRemainsReceivedThroughRealAgentHub(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "node-budget"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	var nodePub ed25519.PublicKey
	mgr, err := probe.NewManager(probe.ManagerConfig{
		Store: st, Keyring: kr, Clock: time.Now, MaxActiveOperations: 1,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) { return nodePub, len(nodePub) != 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	hub, err := agenthub.NewHub(agenthub.Config{
		Store: st, Keyring: kr, Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock: time.Now, ProbeSink: mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)
	key := enrollRaw(t, hub, st, nodeID)
	nodePub = key.PublicKey()
	conn := dialRawAgent(t, hub, st, srv.URL, nodeID, key)
	defer conn.conn.CloseNow()

	first := testReceiptArm(1, "budget-provider")
	target := testReceiptArm(2, "budget-provider")
	expiresAt := time.Now().Add(time.Minute).Unix()
	for i, arm := range []protocol.ProbeArm{first, target} {
		if _, err := st.CreateProbeOperation(store.ProbeOperation{
			ID: fmt.Sprintf("budget-operation-%d", i), NodeID: nodeID, ProviderID: "budget-provider",
			Status: "PENDING", Endpoint: arm.Endpoint, ArmHex: hex.EncodeToString(arm.Canonical()),
			TTLMS: arm.TTLMS, ExpiryOpaque: hex.EncodeToString(arm.ExpiryOpaque[:]), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetProbeOperationStatus("budget-operation-1", "ARMED"); err != nil {
		t.Fatal(err)
	}
	challenge := [32]byte{0x44}
	if err := st.SetProbeOperationChallenge("budget-operation-1", hex.EncodeToString(challenge[:])); err != nil {
		t.Fatal(err)
	}
	payload := signedReceipt(key, target, challenge)
	digest := sha256.Sum256(payload)
	operationID := hex.EncodeToString(digest[:])
	messageID := security.MessageID(operationID, "probe_ingress_receipt")
	ctx := context.Background()
	events, stopReader := startProbeC2AReader(conn)
	defer stopReader()
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatal(err)
	}
	state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:]))
	if state != "RECEIVED" {
		t.Fatalf("lookup-budget inbox state = %q, want RECEIVED", state)
	}
	assertNoProbeSemanticAck(t, events, 150*time.Millisecond)
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after lookup-budget error: %v", err)
	}
	if err := st.SetProbeOperationStatus("budget-operation-0", string(protocol.OutcomeRejected)); err != nil {
		t.Fatal(err)
	}
	if err := sendA2CExact(ctx, conn, 3, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay repaired lookup receipt: %v", err)
	}
	if got := waitProbeSemanticAck(t, events, operationID); got != operationID {
		t.Fatalf("repaired lookup receipt operation id = %q, want %q", got, operationID)
	}
	if state := waitControlInboxState(t, st, hex.EncodeToString(messageID[:])); state != "PROCESSED" {
		t.Fatalf("repaired lookup inbox state = %q, want PROCESSED", state)
	}
	results, err := st.ListProbeResults("budget-operation-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Kind != "rct1" || results[0].PayloadHex != hex.EncodeToString(payload) {
		t.Fatalf("lookup results after repair = %+v, want one exact rct1", results)
	}
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after lookup repair: %v", err)
	}
}

// A permanent receipt may be acknowledged only after its terminal inbox
// disposition is durable. If the REJECTED transition fails, the exact receipt
// remains RECEIVED and the same session can replay it after repair.
func TestProbeArmedInboxStateFailureReplaysToSemanticAck(t *testing.T) {
	sink := &probeSinkRecorder{}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-armed-rpl"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	operationID := "probe-armed-replay"
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: operationID, MessageType: "probe_arm", NodeID: nodeID,
		SemanticPayload: "ARM1-frame",
	}); err != nil {
		t.Fatal(err)
	}
	commandID := security.MessageID(operationID, "probe_arm")
	agentOperationID := hex.EncodeToString(commandID[:])
	resultID := security.MessageID(agentOperationID, "operation_complete")
	resultMessageID := hex.EncodeToString(resultID[:])
	payload := []byte("RDY1-frame")
	rawDB := openAgentHubRawDB(t, st)
	trigger := fmt.Sprintf(`CREATE TRIGGER test_probe_armed_processed_once
		BEFORE UPDATE OF state ON control_inbox
		WHEN OLD.message_id = '%s' AND OLD.state = 'RECEIVED' AND NEW.state = 'PROCESSED'
		BEGIN SELECT RAISE(ABORT, 'injected probe_armed inbox state failure'); END`, resultMessageID)
	if _, err := rawDB.Exec(trigger); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	events, stopReader := startProbeC2AReader(conn)
	defer stopReader()
	if err := sendA2CExact(ctx, conn, 1, resultID, "operation_complete", payload); err != nil {
		t.Fatal(err)
	}
	item, err := waitControlInboxItem(t, st, resultMessageID)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "RECEIVED" || item.SemanticPayload != string(payload) {
		t.Fatalf("failed probe_armed inbox item = %+v, want RECEIVED with exact payload", item)
	}
	if sink.count() != 1 {
		t.Fatalf("first probe_armed sink calls = %d, want 1", sink.count())
	}
	assertNoProbeSemanticAck(t, events, 150*time.Millisecond)
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after probe_armed state failure: %v", err)
	}
	if _, err := rawDB.Exec(`DROP TRIGGER test_probe_armed_processed_once`); err != nil {
		t.Fatal(err)
	}

	if err := sendA2CExact(ctx, conn, 3, resultID, "operation_complete", payload); err != nil {
		t.Fatal(err)
	}
	if got := waitProbeSemanticAck(t, events, agentOperationID); got != agentOperationID {
		t.Fatalf("probe_armed replay semantic ACK operation id = %q, want %q", got, agentOperationID)
	}
	item, err = waitControlInboxItem(t, st, resultMessageID)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "PROCESSED" || item.SemanticPayload != string(payload) {
		t.Fatalf("replayed probe_armed inbox item = %+v, want PROCESSED with exact payload", item)
	}
	if sink.count() != 2 {
		t.Fatalf("replayed probe_armed sink calls = %d, want 2", sink.count())
	}
	row, err := st.ControlOutboxItemByOperation(operationID, "probe_arm")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "SEMANTIC_ACKED" {
		t.Fatalf("probe_arm outbox state = %q, want SEMANTIC_ACKED", row.State)
	}
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after probe_armed replay: %v", err)
	}
}

func TestProbeReceiptRejectionStateFailureRemainsRetryable(t *testing.T) {
	sink := markedPermanentProbeSink{err: store.ErrNotFound}
	hub, st, srv := newSinkHub(t, sink)
	nodeID := "node-reject"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	payload := []byte("authenticated-permanent-receipt")
	operationID, messageID := actualProbeMessageID(payload, "probe_ingress_receipt")
	messageHex := hex.EncodeToString(messageID[:])
	rawDB := openAgentHubRawDB(t, st)
	trigger := fmt.Sprintf(`CREATE TRIGGER test_reject_once
		BEFORE UPDATE OF state ON control_inbox
		WHEN OLD.message_id = '%s' AND OLD.state = 'RECEIVED' AND NEW.state = 'NACKED'
		BEGIN SELECT RAISE(ABORT, 'injected RejectControlInbox failure'); END`, messageHex)
	if _, err := rawDB.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	events, stopReader := startProbeC2AReader(conn)
	defer stopReader()
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatal(err)
	}
	item, err := waitControlInboxItem(t, st, messageHex)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "RECEIVED" || item.SemanticPayload != string(payload) {
		t.Fatalf("failed rejection item = %+v, want RECEIVED with exact payload", item)
	}
	assertNoProbeSemanticAck(t, events, 150*time.Millisecond)
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after rejection-state failure: %v", err)
	}
	if _, err := rawDB.Exec(`DROP TRIGGER test_reject_once`); err != nil {
		t.Fatal(err)
	}

	if err := sendA2CExact(ctx, conn, 3, messageID, "probe_ingress_receipt", payload); err != nil {
		t.Fatalf("replay permanent receipt: %v", err)
	}
	if got := waitProbeSemanticAck(t, events, operationID); got != operationID {
		t.Fatalf("rejection semantic receipt operation_id = %q, want %q", got, operationID)
	}
	item, err = waitControlInboxItem(t, st, messageHex)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "NACKED" || item.SemanticPayload != string(payload) {
		t.Fatalf("replayed rejection item = %+v, want NACKED with exact payload", item)
	}
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after rejection repair: %v", err)
	}
}

func testReceiptArm(seed byte, provider string) protocol.ProbeArm {
	var arm protocol.ProbeArm
	arm.ProbeID[0] = seed
	copy(arm.ProviderID[:], provider)
	arm.ProviderPublicKey[0] = seed + 1
	arm.ExpectedSourceIP = [4]byte{198, 51, 100, 9}
	arm.Activation[0] = seed + 10
	arm.Endpoint = "198.51.100.7:8080"
	arm.TTLMS = 30_000
	arm.ExpiryOpaque[0] = seed + 20
	return arm
}

func signedReceipt(key *security.NodeKey, arm protocol.ProbeArm, challenge [32]byte) []byte {
	receipt := protocol.ProbeReceipt{ArmDigest: arm.Digest(), ChallengeHash: challenge}
	copy(receipt.ProviderID[:], arm.ProviderID[:])
	receipt.Signature = ed25519.Sign(key.PrivateKey(), receipt.SigningBytes())
	return append(receipt.SigningBytes(), receipt.Signature...)
}

type probeC2AEvent struct {
	messageType string
	operationID string
}

func startProbeC2AReader(conn *rawAgentConn) (<-chan probeC2AEvent, func()) {
	events := make(chan probeC2AEvent, 8)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(events)
		for {
			_, raw, err := conn.conn.Read(ctx)
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
				events <- probeC2AEvent{messageType: env.Header.MessageType, operationID: payload.OperationID}
			}
		}
	}()
	return events, cancel
}

func assertNoProbeSemanticAck(t *testing.T, events <-chan probeC2AEvent, window time.Duration) {
	t.Helper()
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case event := <-events:
		t.Fatalf("unexpected semantic probe ACK: %+v", event)
	case <-timer.C:
	}
}

func waitProbeSemanticAck(t *testing.T, events <-chan probeC2AEvent, want string) string {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("probe C2A reader closed before semantic ACK")
			}
			if event.operationID == want {
				return event.operationID
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for semantic ACK %q", want)
		}
	}
}

func openAgentHubRawDB(t *testing.T, st *store.Store) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+st.Path()+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatalf("open agenthub raw database: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func waitControlInboxItem(t *testing.T, st *store.Store, messageID string) (store.ControlInboxItem, error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		item, err := st.ControlInboxItemByMessageID(messageID)
		if err == nil {
			return item, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return store.ControlInboxItem{}, fmt.Errorf("wait inbox item %q: %w", messageID, lastErr)
}
