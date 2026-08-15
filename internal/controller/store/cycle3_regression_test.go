package store

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestSetProbeOperationStatusCannotPublishVerifiedOutcome protects the
// publication boundary: OPEN_FROM_VANTAGE is the result of the complete
// provider/WAN1/ACK1/RCT1 join, not a generic status update.
func TestSetProbeOperationStatusCannotPublishVerifiedOutcome(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "node-1")
	mustCreateForward(t, s, Forward{ID: "forward-1", NodeID: "node-1", Name: "forward-1", Protocol: "tcp"})
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID:           "probe-status-boundary",
		NodeID:       "node-1",
		ForwardID:    "forward-1",
		ActivationID: "activation-1",
		ProviderID:   "provider-1",
		Status:       "IN_FLIGHT",
		Endpoint:     "198.51.100.7:8080",
		ArmHex:       "41524d31",
		TTLMS:        30000,
		ExpiryOpaque: "00112233445566778899aabbccddeeff",
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("create probe operation: %v", err)
	}

	if err := s.SetProbeOperationStatus("probe-status-boundary", string(protocol.OutcomeOpenFromVantage)); err == nil {
		t.Fatal("generic status update published OPEN_FROM_VANTAGE without a join")
	}
	got, err := s.GetProbeOperation("probe-status-boundary")
	if err != nil {
		t.Fatalf("get probe operation: %v", err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("status changed after rejected publication attempt: %q", got.Status)
	}
}

type probeJoinFixture struct {
	store        *Store
	operationID  string
	forwardID    string
	activationID string
	arm          protocol.ProbeArm
	frame        protocol.ProviderFrame
}

func newProbeJoinFixture(t *testing.T, frameActivation [protocol.ProbeActivationLen]byte, ackDigest [protocol.ProbeDigestLen]byte, malformedACK bool) probeJoinFixture {
	t.Helper()
	s := openTestStore(t)
	if err := s.CreateNode(Node{ID: "node-join", Name: "node-join"}); err != nil {
		t.Fatalf("create node: %v", err)
	}

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
	activationID := hex.EncodeToString(activation[:])
	providerIDText := hex.EncodeToString(providerID[:])
	operationID := hex.EncodeToString(probeID[:])
	forwardID := "forward-join"

	if _, err := s.CreateForward(Forward{
		ID:                  forwardID,
		NodeID:              "node-join",
		Name:                "join",
		Protocol:            "tcp",
		Revision:            1,
		CurrentActivationID: activationID,
	}); err != nil {
		t.Fatalf("create forward: %v", err)
	}
	if _, err := s.CreateProbeProvider(ProbeProvider{
		ID:                 providerIDText,
		Name:               "provider-join",
		PublicKey:          hex.EncodeToString(providerKey[:]),
		EgressIP:           "198.51.100.9",
		Endpoint:           "https://provider.invalid",
		Enabled:            true,
		IndependentVantage: true,
	}); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	arm := protocol.ProbeArm{
		ProbeID:           probeID,
		ProviderID:        providerID,
		ProviderPublicKey: providerKey,
		ExpectedSourceIP:  source,
		Activation:        activation,
		Endpoint:          "198.51.100.7:8080",
		TTLMS:             30000,
		ExpiryOpaque:      opaque,
	}
	if err := arm.Validate(); err != nil {
		t.Fatalf("validate fixture arm: %v", err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID:            operationID,
		NodeID:        "node-join",
		ForwardID:     forwardID,
		ActivationID:  activationID,
		ProviderID:    providerIDText,
		Status:        "IN_FLIGHT",
		Endpoint:      arm.Endpoint,
		ArmHex:        hex.EncodeToString(arm.Canonical()),
		ChallengeHash: "",
		TTLMS:         arm.TTLMS,
		ExpiryOpaque:  hex.EncodeToString(arm.ExpiryOpaque[:]),
		ExpiresAt:     time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("create operation: %v", err)
	}

	frame := protocol.ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   frameActivation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    [protocol.ProbeNonceLen]byte{9, 8, 7, 6},
		Signature:    make([]byte, 64),
	}
	challengeHash := frame.ChallengeHash()
	if err := s.SetProbeOperationChallenge(operationID, hex.EncodeToString(challengeHash[:])); err != nil {
		t.Fatalf("set challenge: %v", err)
	}

	wan1 := append(frame.Canonical(), frame.Signature...)
	var ack []byte
	if malformedACK {
		ack = []byte("not-an-ack1-frame")
	} else {
		ackFrame := protocol.ProbeACK{
			ArmDigest:     ackDigest,
			ChallengeHash: challengeHash,
			Signature:     make([]byte, 64),
		}
		ack = append(ackFrame.SigningBytes(), ackFrame.Signature...)
	}
	receiptFrame := protocol.ProbeReceipt{
		ArmDigest:     arm.Digest(),
		ChallengeHash: challengeHash,
		ProviderID:    arm.ProviderID,
		Signature:     make([]byte, 64),
	}
	rct1 := append(receiptFrame.SigningBytes(), receiptFrame.Signature...)
	providerPayload, err := json.Marshal(map[string]any{
		"probe_id":       operationID,
		"accepted":       true,
		"challenge_hash": hex.EncodeToString(challengeHash[:]),
		"wan1_frame":     hex.EncodeToString(wan1),
		"ack1_frame":     hex.EncodeToString(ack),
	})
	if err != nil {
		t.Fatalf("marshal provider fixture: %v", err)
	}
	for _, result := range []struct {
		kind    string
		payload string
	}{
		{kind: "provider", payload: string(providerPayload)},
		{kind: "wan1", payload: hex.EncodeToString(wan1)},
		{kind: "ack1", payload: hex.EncodeToString(ack)},
		{kind: "rct1", payload: hex.EncodeToString(rct1)},
	} {
		if err := s.RecordProbeResult(operationID, result.kind, result.payload); err != nil {
			t.Fatalf("record %s: %v", result.kind, err)
		}
	}
	return probeJoinFixture{
		store:        s,
		operationID:  operationID,
		forwardID:    forwardID,
		activationID: activationID,
		arm:          arm,
		frame:        frame,
	}
}

func legalProbeSnapshot() string {
	return `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"HEALTHY","wan_reachability_state":"OPEN_FROM_VANTAGE","return_path_state":"VERIFIED","target_health_state":"PASS","publication_state":"PUBLISHED_VERIFIED","data_plane_state":"READY"}`
}

func legalRuntimeSnapshot(wan, returnPath, publication string) string {
	return fmt.Sprintf(`{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"HEALTHY","wan_reachability_state":%q,"return_path_state":%q,"target_health_state":"PASS","publication_state":%q,"data_plane_state":"READY"}`, wan, returnPath, publication)
}

// TestSetForwardRuntimeStatusRejectsContradictoryPublication protects the
// orthogonal activation contract even when a caller bypasses probe joining.
func TestSetForwardRuntimeStatusRejectsContradictoryPublication(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateNode(Node{ID: "node-runtime", Name: "node-runtime"}); err != nil {
		t.Fatalf("create node: %v", err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "forward-runtime", NodeID: "node-runtime", Name: "runtime", Protocol: "tcp",
		Revision: 1, CurrentActivationID: "activation-runtime",
	}); err != nil {
		t.Fatalf("create forward: %v", err)
	}
	contradictory := legalRuntimeSnapshot("NOT_TESTED", "UNKNOWN", "PUBLISHED_VERIFIED")
	if err := s.SetForwardRuntimeStatus("forward-runtime", "activation-runtime", contradictory); err == nil {
		t.Fatal("contradictory runtime snapshot was persisted")
	}
	if _, err := s.GetForwardRuntimeStatus("forward-runtime"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("contradictory snapshot left a runtime row: %v", err)
	}
}

// TestPublishProbeJoinRejectsMismatchedWireEvidence ensures the durable join
// fence checks the decoded WAN1 fields, not merely the presence of four rows.
func TestPublishProbeJoinRejectsMismatchedWireEvidence(t *testing.T) {
	var mismatchedActivation [protocol.ProbeActivationLen]byte
	for i := range mismatchedActivation {
		mismatchedActivation[i] = byte(i + 201)
	}
	fixture := newProbeJoinFixture(t, mismatchedActivation, [protocol.ProbeDigestLen]byte{}, true)
	if err := fixture.store.PublishProbeJoin(fixture.operationID, "IN_FLIGHT", fixture.forwardID, fixture.activationID, legalProbeSnapshot()); err == nil {
		t.Fatal("join accepted malformed/mismatched WAN1 and ACK1 evidence")
	}
	got, err := fixture.store.GetProbeOperation(fixture.operationID)
	if err != nil {
		t.Fatalf("get operation after rejected join: %v", err)
	}
	if got.Status == string(protocol.OutcomeOpenFromVantage) {
		t.Fatal("malformed/mismatched evidence published OPEN_FROM_VANTAGE")
	}
}

// TestPublishProbeJoinRejectsWrongPathACK ensures an ACK1 for another arm
// cannot satisfy the same-path join even when all evidence rows are present.
func TestPublishProbeJoinRejectsWrongPathACK(t *testing.T) {
	fixture := newProbeJoinFixture(t, fixtureActivationSeed(), [protocol.ProbeDigestLen]byte{}, false)
	if err := fixture.store.PublishProbeJoin(fixture.operationID, "IN_FLIGHT", fixture.forwardID, fixture.activationID, legalProbeSnapshot()); err == nil {
		t.Fatal("join accepted an ACK1 bound to a different operation")
	}
}

func fixtureActivationSeed() [protocol.ProbeActivationLen]byte {
	var activation [protocol.ProbeActivationLen]byte
	for i := range activation {
		activation[i] = byte(i + 33)
	}
	return activation
}
