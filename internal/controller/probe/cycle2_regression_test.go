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

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestProviderBindsExpectedSourceIP is Story 1 cycle-2 RED evidence: a
// provider request that pins an egress address must not be satisfied by a
// connection made from an unrelated local source address.
func TestProviderBindsExpectedSourceIP(t *testing.T) {
	ctrlPub, ctrlPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
		DialTimeout:         2 * time.Second,
		ExchangeTimeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	ln, endpoint := globalTestEndpoint(t)

	nodePub, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	var armDigest [32]byte
	var probeID, providerID, activation, opaque [16]byte
	rand.Read(armDigest[:])
	rand.Read(probeID[:])
	rand.Read(providerID[:])
	rand.Read(activation[:])
	rand.Read(opaque[:])

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, err := readWAN1(conn)
		if err != nil {
			return
		}
		frame, err := protocol.ParseProviderFrame(raw)
		if err != nil {
			return
		}
		chash := frame.ChallengeHash()
		ackBody := append([]byte(protocol.ProbeMagicACK), armDigest[:]...)
		ackBody = append(ackBody, chash[:]...)
		_, _ = conn.Write(append(ackBody, ed25519.Sign(nodePriv, ackBody)...))
	}()

	req := providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "k1",
		NodePublicKey: hex.EncodeToString(nodePub), NodePublicKeyHash: hex.EncodeToString(hash256(nodePub)),
		ProbeID: hex.EncodeToString(probeID[:]), ProviderID: hex.EncodeToString(providerID[:]),
		Activation: hex.EncodeToString(activation[:]), Endpoint: endpoint,
		// 203.0.113.9 is deliberately not the actual source address. The
		// current implementation ignores this field and incorrectly accepts.
		ExpectedSourceIP: "cb007109", ExpiryOpaque: hex.EncodeToString(opaque[:]),
		TTLMS: 30000, ArmDigest: hex.EncodeToString(armDigest[:]), TimestampUnix: time.Now().Unix(),
	}
	canonical, _ := req.canonical()
	req.Signature = hex.EncodeToString(ed25519.Sign(ctrlPriv, canonical))
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/probe/v1/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result providerResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("provider accepted an exchange from the wrong expected source")
	}
}

// TestAgentProbeResultCannotSelfPublish is Story 2 cycle-2 RED evidence:
// OPEN_FROM_VANTAGE is reserved for the provider/WAN1/ACK1/RCT1 join and
// cannot be asserted by an agent result message.
func TestAgentProbeResultCannotSelfPublish(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, _ := env.armAndGetPayload(t, "198.51.100.7:8080")
	payload, err := json.Marshal(map[string]string{
		"probe_id": op.ID, "outcome": string(protocol.OutcomeOpenFromVantage),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.manager.handleProbeResult("n1", payload); err == nil {
		t.Fatal("agent self-published OPEN_FROM_VANTAGE")
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == string(protocol.OutcomeOpenFromVantage) {
		t.Fatal("agent result changed operation to OPEN_FROM_VANTAGE")
	}
}

// TestVerifiedJoinStoresFrozenLegalSnapshot is Story 3 cycle-2 RED evidence:
// a verified join must persist only values from the frozen activation enums.
func TestVerifiedJoinStoresFrozenLegalSnapshot(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	ln, endpoint := globalTestEndpoint(t)
	op, arm := env.armAndGetPayload(t, endpoint)

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		raw, err := readWAN1(conn)
		if err != nil {
			done <- err
			return
		}
		frame, err := protocol.ParseProviderFrame(raw)
		if err != nil {
			done <- err
			return
		}
		chash := frame.ChallengeHash()
		digest := arm.Digest()
		ackBody := append([]byte(protocol.ProbeMagicACK), digest[:]...)
		ackBody = append(ackBody, chash[:]...)
		if _, err := conn.Write(append(ackBody, ed25519.Sign(env.nodePriv, ackBody)...)); err != nil {
			done <- err
			return
		}
		done <- handleReceiptEventually(t, env, signRCT1(t, env.nodePriv, arm, chash))
	}()
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := env.store.GetProbeOperation(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != string(protocol.OutcomeOpenFromVantage) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		status, err := env.store.GetForwardRuntimeStatus(op.ForwardID)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot protocol.ActivationStates
		if err := json.Unmarshal([]byte(status.SnapshotJSON), &snapshot); err != nil {
			t.Fatal(err)
		}
		if err := snapshot.Validate(); err != nil {
			t.Fatalf("verified join persisted an illegal activation snapshot: %v", err)
		}
		return
	}
	t.Fatal("operation never reached OPEN_FROM_VANTAGE")
}
