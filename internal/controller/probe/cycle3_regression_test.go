package probe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestLateReceiptTransitionsToTimeout ensures a receipt that arrives after
// the operation deadline cannot remain live or reach the join routine.
func TestLateReceiptTransitionsToTimeout(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	var probeID [protocol.ProbeIDLen]byte
	var providerID [protocol.ProbeProviderIDLen]byte
	var activation [protocol.ProbeActivationLen]byte
	var source [4]byte
	var opaque [protocol.ProbeOpaqueLen]byte
	var providerKey [32]byte
	for i := range probeID {
		probeID[i] = byte(i + 1)
		providerID[i] = byte(i + 17)
		activation[i] = byte(i + 33)
		opaque[i] = byte(i + 65)
		providerKey[i] = byte(i + 97)
	}
	copy(source[:], []byte{198, 51, 100, 9})
	arm := protocol.ProbeArm{
		ProbeID: probeID, ProviderID: providerID, ProviderPublicKey: providerKey,
		ExpectedSourceIP: source, Activation: activation, Endpoint: "198.51.100.7:8080",
		TTLMS: 30000, ExpiryOpaque: opaque,
	}
	if err := arm.Validate(); err != nil {
		t.Fatalf("validate late-receipt arm: %v", err)
	}
	lateID := "late-receipt"
	if _, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID: lateID, NodeID: "n1", ForwardID: "f1", ActivationID: "act-1", ProviderID: "prov-1",
		Status: "IN_FLIGHT", Endpoint: arm.Endpoint, ArmHex: hex.EncodeToString(arm.Canonical()),
		TTLMS: arm.TTLMS, ExpiryOpaque: hex.EncodeToString(arm.ExpiryOpaque[:]), ExpiresAt: 1,
	}); err != nil {
		t.Fatalf("create expired operation: %v", err)
	}

	// The frame is correctly signed, but it is delivered after expiry.
	_ = env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", signRCT1(t, env.nodePriv, arm, [32]byte{1}))
	got, err := env.store.GetProbeOperation(lateID)
	if err != nil {
		t.Fatalf("get expired operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeTimeout) {
		t.Fatalf("late receipt left status %q, want TIMEOUT", got.Status)
	}
}

// TestProbeResultRejectsUnknownJSONFields keeps the authenticated telemetry
// decoder fail-closed. Unknown fields must not be able to smuggle a different
// interpretation into the probe state machine.
func TestProbeResultRejectsUnknownJSONFields(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, _ := env.armAndGetPayload(t, "198.51.100.7:8080")
	payload := []byte(`{"probe_id":"` + op.ID + `","outcome":"REJECTED","unexpected":true}`)
	if err := env.manager.handleProbeResult("n1", payload); err == nil {
		t.Fatal("probe_result with an unknown field was accepted")
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != "PENDING" {
		t.Fatalf("malformed probe_result changed status to %q", got.Status)
	}
}

func signedProviderRequest(t *testing.T, priv ed25519.PrivateKey, probeID, digest, source string, now int64) []byte {
	t.Helper()
	nodePub := make([]byte, ed25519.PublicKeySize)
	for i := range nodePub {
		nodePub[i] = byte(i + 1)
	}
	req := providerRequest{
		Schema:             providerRequestSchema,
		ControllerInstance: "controller-1",
		ControllerKeyID:    "key-1",
		NodePublicKey:      hex.EncodeToString(nodePub),
		NodePublicKeyHash:  hex.EncodeToString(hash256(nodePub)),
		ProbeID:            probeID,
		ProviderID:         "22222222222222222222222222222222",
		Activation:         "33333333333333333333333333333333",
		Endpoint:           "198.51.100.7:1",
		ExpectedSourceIP:   source,
		ExpiryOpaque:       "44444444444444444444444444444444",
		TTLMS:              30000,
		ArmDigest:          digest,
		TimestampUnix:      now,
	}
	canonical, err := req.canonical()
	if err != nil {
		t.Fatalf("canonical provider request: %v", err)
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(priv, canonical))
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal provider request: %v", err)
	}
	return body
}

// TestProviderRejectsPrivateExpectedSource covers the source-policy boundary:
// a signed request may not turn a private/loopback address into provider WAN
// evidence merely because the endpoint itself is globally valid.
func TestProviderRejectsPrivateExpectedSource(t *testing.T) {
	controllerPub, controllerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := signedProviderRequest(t, controllerPriv,
		"11111111111111111111111111111111",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"7f000001", 1000)
	if _, err := decodeProviderRequestAt(bytes.NewReader(body), controllerPub, time.Unix(1000, 0)); err == nil {
		t.Fatal("provider accepted a private expected source address")
	}
}

// TestProviderReplayDifferentMaterialIsConflict pins the frozen distinction
// between an identical replay and reuse of a consumed probe ID with different
// signed material. The latter must not be treated as a harmless replay.
func TestProviderReplayDifferentMaterialIsConflict(t *testing.T) {
	controllerPub, controllerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: controllerPub,
		ProviderPrivateKey:  providerPriv,
		DialTimeout:         10 * time.Millisecond,
		ExchangeTimeout:     10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	for i, digest := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		body := signedProviderRequest(t, controllerPriv,
			"55555555555555555555555555555555", digest, "c6336409", time.Now().Unix())
		resp, err := http.Post(srv.URL+"/probe/v1/request", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var result providerResult
		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if i == 1 && result.Reason != "conflict" {
			t.Fatalf("different-material reuse reason = %q, want conflict", result.Reason)
		}
	}
}
