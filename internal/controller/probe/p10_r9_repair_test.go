package probe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func TestProviderReplayReturnsCachedSignedResult(t *testing.T) {
	controllerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPriv})
	if err != nil {
		t.Fatal(err)
	}
	req := &providerRequest{Schema: providerRequestSchema, ProbeID: "AABB", TimestampUnix: time.Now().Unix()}
	now := time.Now()
	if reason := p.admitReplay(req, now); reason != "" {
		t.Fatalf("first admission = %q", reason)
	}
	recorder := httptest.NewRecorder()
	p.writeResult(recorder, providerResult{ProbeID: req.ProbeID, Reason: "unreachable", cacheKey: replayKey(req)})
	var first providerResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if reason := p.admitReplay(req, now.Add(time.Second)); reason != "replay" {
		t.Fatalf("second admission = %q, want replay", reason)
	}
	cached, ok := p.cachedReplayResult(req, now.Add(time.Second))
	if !ok || cached.Signature != first.Signature || cached.TimestampUnix != first.TimestampUnix {
		t.Fatalf("cached result = %+v, first = %+v", cached, first)
	}
}

func TestRecoverOperationsRequeuesTerminalOutcome(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID:           "terminal-recovery",
		NodeID:       "n1",
		ForwardID:    "f1",
		ActivationID: "act-1",
		ProviderID:   "prov-1",
		Status:       string(protocol.OutcomeRejected),
		Endpoint:     "198.51.100.7:8080",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.manager.recoverOperations()
	item, err := env.store.ControlOutboxItemByOperation(op.ID, "probe_outcome")
	if err != nil {
		t.Fatalf("terminal outcome was not requeued: %v", err)
	}
	var payload struct {
		ForwardID  string `json:"forward_id"`
		Activation string `json:"activation"`
		Generation uint64 `json:"generation"`
		Outcome    string `json:"outcome"`
	}
	if err := json.Unmarshal([]byte(item.SemanticPayload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ForwardID != "f1" || payload.Activation != "act-1" || payload.Generation != 1 || payload.Outcome != string(protocol.OutcomeRejected) {
		t.Fatalf("unexpected outcome payload: %+v", payload)
	}
}

func TestSweepRequeuesExpiredTimeoutOutcome(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID: "expired-timeout", NodeID: "n1", ForwardID: "f1", ActivationID: "act-1", ProviderID: "prov-1",
		Status: "PENDING", Endpoint: "198.51.100.7:8080", ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.manager.sweepOnce(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.ControlOutboxItemByOperation(op.ID, "probe_outcome"); err != nil {
		t.Fatalf("expired timeout outcome was not queued: %v", err)
	}
}

func TestHandleActivationStatusRejectsGenerationOutsideCurrentRevision(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	states := protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
		KeepaliveState: "HEALTHY", WanReachabilityState: "NOT_TESTED",
		ReturnPathState: "NOT_TESTED", TargetHealthState: "UNKNOWN",
		PublicationState: "NONE", DataPlaneState: "READY",
	}
	for _, generation := range []uint64{0, 2} {
		payload, err := json.Marshal(struct {
			ForwardID  string                    `json:"forward_id"`
			Activation string                    `json:"activation"`
			Generation uint64                    `json:"generation"`
			Snapshot   protocol.ActivationStates `json:"snapshot"`
		}{"f1", "act-1", generation, states})
		if err != nil {
			t.Fatal(err)
		}
		if err := env.manager.HandleActivationStatus("n1", payload); err == nil {
			t.Fatalf("generation %d was accepted", generation)
		}
	}

	payload, err := json.Marshal(struct {
		ForwardID  string                    `json:"forward_id"`
		Activation string                    `json:"activation"`
		Generation uint64                    `json:"generation"`
		Snapshot   protocol.ActivationStates `json:"snapshot"`
	}{"f1", "act-1", 1, states})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.manager.HandleActivationStatus("n1", payload); err != nil {
		t.Fatalf("current generation rejected: %v", err)
	}
}
