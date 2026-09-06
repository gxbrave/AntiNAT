package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// authenticatedJoinFixture builds a complete, cryptographically valid join
// journal. The tests below replace exactly one Agent signature with a
// non-zero forged value; a non-zero check alone must not be sufficient to
// publish OPEN_FROM_VANTAGE.
type authenticatedJoinFixture struct {
	store          *Store
	operationID    string
	forwardID      string
	activationID   string
	providerPriv   ed25519.PrivateKey
	providerResult storedProviderResult
	ackPayload     []byte
	receiptPayload []byte
}

func newAuthenticatedJoinFixture(t *testing.T) authenticatedJoinFixture {
	t.Helper()
	s := openTestStore(t)
	const nowUnix int64 = 2_000_000
	withStoreNow(t, nowUnix)

	if err := s.CreateNode(Node{ID: "join-node", Name: "join-node"}); err != nil {
		t.Fatalf("create node: %v", err)
	}
	providerSeed := bytes.Repeat([]byte{0x21}, ed25519.SeedSize)
	providerPriv := ed25519.NewKeyFromSeed(providerSeed)
	providerPub := providerPriv.Public().(ed25519.PublicKey)
	nodeSeed := bytes.Repeat([]byte{0x31}, ed25519.SeedSize)
	nodePriv := ed25519.NewKeyFromSeed(nodeSeed)

	var probeID, providerID, activation, opaque [16]byte
	for i := range probeID {
		probeID[i] = byte(i + 1)
		providerID[i] = byte(i + 33)
		activation[i] = byte(i + 65)
		opaque[i] = byte(i + 97)
	}
	operationID := hex.EncodeToString(probeID[:])
	providerTextID := hex.EncodeToString(providerID[:])
	activationID := hex.EncodeToString(activation[:])
	forwardID := "join-forward"
	if _, err := s.CreateForward(Forward{
		ID: forwardID, NodeID: "join-node", Name: "join", Protocol: "tcp",
		CurrentActivationID: activationID, Revision: 1,
	}); err != nil {
		t.Fatalf("create forward: %v", err)
	}
	if _, err := s.CreateProbeProvider(ProbeProvider{
		ID: providerTextID, Name: "independent", PublicKey: hex.EncodeToString(providerPub),
		EgressIP: "198.51.100.9", Endpoint: "https://provider.invalid",
		Enabled: true, IndependentVantage: true,
	}); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	var source [4]byte
	copy(source[:], []byte{198, 51, 100, 9})
	arm := protocol.ProbeArm{
		ProbeID: probeID, ProviderID: providerID, ProviderPublicKey: [32]byte(providerPub),
		ExpectedSourceIP: source, Activation: activation,
		Endpoint: "198.51.100.7:8080", TTLMS: 30_000, ExpiryOpaque: opaque,
	}
	if err := arm.Validate(); err != nil {
		t.Fatalf("validate arm: %v", err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: operationID, NodeID: "join-node", ForwardID: forwardID, ActivationID: activationID,
		ProviderID: providerTextID, Status: "IN_FLIGHT", Endpoint: arm.Endpoint,
		ArmHex: hex.EncodeToString(arm.Canonical()), TTLMS: arm.TTLMS,
		ExpiryOpaque: hex.EncodeToString(opaque[:]), ExpiresAt: nowUnix + 30,
	}); err != nil {
		t.Fatalf("create operation: %v", err)
	}

	var challenge [32]byte
	for i := range challenge {
		challenge[i] = byte(i + 11)
	}
	frame := protocol.ProviderFrame{
		ArmDigest: arm.Digest(), ProbeID: probeID, ProviderID: providerID,
		Activation: activation, Endpoint: arm.Endpoint, ExpiryOpaque: opaque,
		Challenge: challenge,
	}
	frame.Signature = ed25519.Sign(providerPriv, frame.SigningBytes())
	wan1 := append(append([]byte(nil), frame.Canonical()...), frame.Signature...)
	challengeHash := frame.ChallengeHash()

	ack := protocol.ProbeACK{ArmDigest: arm.Digest(), ChallengeHash: challengeHash}
	ack.Signature = ed25519.Sign(nodePriv, ack.SigningBytes())
	ackPayload := append(append([]byte(nil), ack.SigningBytes()...), ack.Signature...)

	receipt := protocol.ProbeReceipt{ArmDigest: arm.Digest(), ChallengeHash: challengeHash, ProviderID: providerID}
	receipt.Signature = ed25519.Sign(nodePriv, receipt.SigningBytes())
	receiptPayload := append(append([]byte(nil), receipt.SigningBytes()...), receipt.Signature...)

	providerResult := storedProviderResult{
		Schema: "antinat.provider-result/v1", ProbeID: operationID, Accepted: true,
		ChallengeHash: hex.EncodeToString(challengeHash[:]),
		WAN1Frame:     hex.EncodeToString(wan1), ACK1Frame: hex.EncodeToString(ackPayload),
		Reason: "ack_verified", TimestampUnix: nowUnix,
	}
	providerResult.Signature = hex.EncodeToString(ed25519.Sign(providerPriv, providerResult.canonical()))
	providerJSON, err := json.Marshal(providerResult)
	if err != nil {
		t.Fatalf("marshal provider result: %v", err)
	}
	if err := s.SetProbeOperationChallenge(operationID, providerResult.ChallengeHash); err != nil {
		t.Fatalf("set challenge: %v", err)
	}
	for _, result := range []struct {
		kind    string
		payload string
	}{
		{kind: "provider", payload: string(providerJSON)},
		{kind: "wan1", payload: hex.EncodeToString(wan1)},
		{kind: "ack1", payload: hex.EncodeToString(ackPayload)},
		{kind: "rct1", payload: hex.EncodeToString(receiptPayload)},
	} {
		if err := s.RecordProbeResult(operationID, result.kind, result.payload); err != nil {
			t.Fatalf("record %s: %v", result.kind, err)
		}
	}
	return authenticatedJoinFixture{
		store: s, operationID: operationID, forwardID: forwardID, activationID: activationID,
		providerPriv: providerPriv, providerResult: providerResult,
		ackPayload: ackPayload, receiptPayload: receiptPayload,
	}
}

const authenticatedJoinSnapshot = `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"HEALTHY","wan_reachability_state":"OPEN_FROM_VANTAGE","return_path_state":"VERIFIED","target_health_state":"PASS","publication_state":"PUBLISHED_VERIFIED","data_plane_state":"READY"}`

func replaceProbeEvidence(t *testing.T, fixture authenticatedJoinFixture, kind string, payload []byte) {
	t.Helper()
	if _, err := fixture.store.db.Exec(`DELETE FROM probe_results WHERE probe_id = ? AND kind = ?`, fixture.operationID, kind); err != nil {
		t.Fatalf("delete %s evidence: %v", kind, err)
	}
	if err := fixture.store.RecordProbeResult(fixture.operationID, kind, hex.EncodeToString(payload)); err != nil {
		t.Fatalf("record forged %s evidence: %v", kind, err)
	}
}

func replaceProviderEvidence(t *testing.T, fixture authenticatedJoinFixture, payload []byte) {
	t.Helper()
	if _, err := fixture.store.db.Exec(`DELETE FROM probe_results WHERE probe_id = ? AND kind = 'provider'`, fixture.operationID); err != nil {
		t.Fatalf("delete provider evidence: %v", err)
	}
	if err := fixture.store.RecordProbeResult(fixture.operationID, "provider", string(payload)); err != nil {
		t.Fatalf("record forged provider evidence: %v", err)
	}
}

func TestPublishProbeJoinRejectsForgedACKSignature(t *testing.T) {
	fixture := newAuthenticatedJoinFixture(t)
	forged := append([]byte(nil), fixture.ackPayload...)
	copy(forged[len(forged)-ed25519.SignatureSize:], bytes.Repeat([]byte{0x42}, ed25519.SignatureSize))
	replaceProbeEvidence(t, fixture, "ack1", forged)
	providerResult := fixture.providerResult
	providerResult.ACK1Frame = hex.EncodeToString(forged)
	providerResult.Signature = hex.EncodeToString(ed25519.Sign(fixture.providerPriv, providerResult.canonical()))
	providerJSON, err := json.Marshal(providerResult)
	if err != nil {
		t.Fatalf("marshal forged provider result: %v", err)
	}
	replaceProviderEvidence(t, fixture, providerJSON)

	if err := fixture.store.PublishProbeJoin(fixture.operationID, "IN_FLIGHT", fixture.forwardID, fixture.activationID, authenticatedJoinSnapshot); err == nil {
		t.Fatal("forged non-zero ACK1 signature published OPEN_FROM_VANTAGE")
	}
	got, err := fixture.store.GetProbeOperation(fixture.operationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("forged ACK1 changed status to %q", got.Status)
	}
}

func TestPublishProbeJoinRejectsForgedReceiptSignature(t *testing.T) {
	fixture := newAuthenticatedJoinFixture(t)
	forged := append([]byte(nil), fixture.receiptPayload...)
	copy(forged[len(forged)-ed25519.SignatureSize:], bytes.Repeat([]byte{0x24}, ed25519.SignatureSize))
	replaceProbeEvidence(t, fixture, "rct1", forged)

	if err := fixture.store.PublishProbeJoin(fixture.operationID, "IN_FLIGHT", fixture.forwardID, fixture.activationID, authenticatedJoinSnapshot); err == nil {
		t.Fatal("forged non-zero RCT1 signature published OPEN_FROM_VANTAGE")
	}
	got, err := fixture.store.GetProbeOperation(fixture.operationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("forged RCT1 changed status to %q", got.Status)
	}
}
