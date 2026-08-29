package agenthub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
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

const integrationRuntimeSnapshot = `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"NOT_REQUIRED","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"UNKNOWN","publication_state":"NONE","data_plane_state":"READY"}`

type gatedProvider struct {
	mu       sync.Mutex
	requests int
	first    chan struct{}
	release  chan struct{}
}

func (p *gatedProvider) handler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	_, _ = io.Copy(io.Discard, r.Body)
	p.mu.Lock()
	p.requests++
	if p.requests == 1 {
		close(p.first)
	}
	p.mu.Unlock()
	<-p.release
	w.WriteHeader(http.StatusInternalServerError)
}

func (p *gatedProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests
}

func waitGatedProviderRequest(t *testing.T, p *gatedProvider) {
	t.Helper()
	select {
	case <-p.first:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first provider request")
	}
}

func waitProbeOperationStatus(t *testing.T, st *store.Store, operationID string, want ...string) store.ProbeOperation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		op, err := st.GetProbeOperation(operationID)
		if err == nil {
			for _, status := range want {
				if op.Status == status {
					return op
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	op, err := st.GetProbeOperation(operationID)
	if err != nil {
		t.Fatalf("read probe operation %q: %v", operationID, err)
	}
	t.Fatalf("probe operation %q status = %q, want one of %v", operationID, op.Status, want)
	return store.ProbeOperation{}
}

func validRDY1(key *security.NodeKey, arm protocol.ProbeArm) []byte {
	digest := arm.Digest()
	body := append([]byte(protocol.ProbeMagicArmed), digest[:]...)
	return append(body, ed25519.Sign(key.PrivateKey(), body)...)
}

// TestRealAgentHubManagerReplayAfterInboxStateFailure exercises the production
// operation_complete path with a real probe.Manager. The first valid RDY1
// durably admits the operation, but an injected inbox state-write failure
// leaves RECEIVED. A duplicate exact result must retry the idempotent Manager
// sink, converge the inbox/outbox state, and never launch a second provider
// request while the original round is still owned.
func TestRealAgentHubManagerReplayAfterInboxStateFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "node-mgr-rpl"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateForward(store.Forward{
		ID: "manager-replay-forward", NodeID: nodeID, Name: "manager-replay-forward",
		Protocol: "tcp", CurrentActivationID: "manager-replay-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetForwardRuntimeStatus("manager-replay-forward", "manager-replay-activation", 1, integrationRuntimeSnapshot); err != nil {
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
		ID: "manager-replay-provider", Name: "manager-replay-provider",
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
	hub, err = agenthub.NewHub(agenthub.Config{
		Store: st, Keyring: kr, Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock: time.Now, ProbeSink: mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	hubSrv := httptest.NewServer(hub.Handler())
	t.Cleanup(hubSrv.Close)

	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, hubSrv.URL, nodeID, key)
	defer conn.conn.CloseNow()

	op, err := mgr.Arm(context.Background(), nodeID, "manager-replay-forward", "manager-replay-activation", "198.51.100.7:8080")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var command protocol.Envelope
	for {
		_, raw, err := conn.conn.Read(ctx)
		if err != nil {
			t.Fatalf("read probe_arm command: %v", err)
		}
		command, _, err = parseEnvelope(raw, hub.ControllerPublicKey())
		if err != nil {
			t.Fatalf("parse probe_arm command: %v", err)
		}
		if command.Header.MessageType == "probe_arm" {
			break
		}
	}
	arm, err := protocol.ParseProbeArm(command.Payload)
	if err != nil {
		t.Fatalf("parse durable ARM1: %v", err)
	}
	payload := validRDY1(key, arm)
	commandID := security.MessageID(op.ID, "probe_arm")
	agentOperationID := hex.EncodeToString(commandID[:])
	resultID := security.MessageID(agentOperationID, "operation_complete")
	resultMessageID := hex.EncodeToString(resultID[:])

	rawDB, err := sql.Open("sqlite", "file:"+st.Path()+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	rawDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = rawDB.Close() })
	trigger := `CREATE TRIGGER test_manager_replay_processed_once
		BEFORE UPDATE OF state ON control_inbox
		WHEN OLD.message_id = '` + resultMessageID + `' AND OLD.state = 'RECEIVED' AND NEW.state = 'PROCESSED'
		BEGIN SELECT RAISE(ABORT, 'injected manager replay inbox state failure'); END`
	if _, err := rawDB.Exec(trigger); err != nil {
		t.Fatal(err)
	}

	events, stopReader := startProbeC2AReader(conn)
	defer stopReader()
	if err := sendA2CExact(ctx, conn, 1, resultID, "operation_complete", payload); err != nil {
		t.Fatalf("send first operation_complete: %v", err)
	}
	item, err := waitControlInboxItem(t, st, resultMessageID)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "RECEIVED" || item.OperationID != agentOperationID || item.SemanticPayload != string(payload) {
		t.Fatalf("first operation_complete inbox = %+v, want RECEIVED exact RDY1 binding", item)
	}
	waitGatedProviderRequest(t, provider)
	if got := provider.count(); got != 1 {
		t.Fatalf("provider requests after first result = %d, want 1", got)
	}
	assertNoProbeSemanticAck(t, events, 150*time.Millisecond)
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after first inbox-state failure: %v", err)
	}

	if _, err := rawDB.Exec(`DROP TRIGGER test_manager_replay_processed_once`); err != nil {
		t.Fatal(err)
	}
	if err := sendA2CExact(ctx, conn, 3, resultID, "operation_complete", payload); err != nil {
		t.Fatalf("send duplicate operation_complete: %v", err)
	}
	if got := waitProbeSemanticAck(t, events, agentOperationID); got != agentOperationID {
		t.Fatalf("semantic ACK operation id = %q, want %q", got, agentOperationID)
	}
	item, err = waitControlInboxItem(t, st, resultMessageID)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "PROCESSED" || item.OperationID != agentOperationID || item.SemanticPayload != string(payload) {
		t.Fatalf("replayed operation_complete inbox = %+v, want PROCESSED exact RDY1 binding", item)
	}
	row, err := st.ControlOutboxItemByOperation(op.ID, "probe_arm")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "SEMANTIC_ACKED" {
		t.Fatalf("probe_arm outbox state = %q, want SEMANTIC_ACKED", row.State)
	}
	if got := provider.count(); got != 1 {
		t.Fatalf("provider requests before releasing first round = %d, want 1", got)
	}

	close(provider.release)
	waitProbeOperationStatus(t, st, op.ID, string(protocol.OutcomeProbeInfraUnavailable))
	time.Sleep(100 * time.Millisecond)
	if got := provider.count(); got != 1 {
		t.Fatalf("provider requests after first round completion = %d, want exactly 1", got)
	}
	if err := conn.sendA2C(ctx, 4, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session did not remain alive after replay convergence: %v", err)
	}
}
