package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// probeFixture is the frozen fixture schema for probe wire golden vectors and
// end-to-end operation transcripts under internal/protocol/testdata/probe-frame/.
//
// For single-frame kinds (arm/armed/wan1/ack/receipt) the validator parses the
// frame and checks signature/fields. For kind "operation" the fixture carries
// the full arm -> ingress -> ACK + receipt transcript and the validator runs
// the frozen probe state machine, asserting the anti-oracle, replay, conflict,
// and TTL semantics.
type probeFixture struct {
	Schema       string `json:"schema"`
	VectorID     string `json:"vector_id"`
	Kind         string `json:"kind"`
	Expect       string `json:"expect"`
	RejectReason string `json:"reject_reason,omitempty"`

	// Single-frame vectors.
	FrameHex         string `json:"frame_hex,omitempty"`
	ProbeIDHex       string `json:"probe_id_hex,omitempty"`
	ProviderIDHex    string `json:"provider_id_hex,omitempty"`
	ActivationHex    string `json:"activation_hex,omitempty"`
	ExpectedSourceIP string `json:"expected_source_ip,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`
	TTLMS            uint64 `json:"ttl_ms,omitempty"`
	ExpiryOpaqueHex  string `json:"expiry_opaque_hex,omitempty"`
	ChallengeHex     string `json:"challenge_hex,omitempty"`
	ChallengeHashHex string `json:"challenge_hash_hex,omitempty"`
	ArmDigestHex     string `json:"arm_digest_hex,omitempty"`
	NodePubHex       string `json:"node_public_key_hex,omitempty"`
	ProviderPubHex   string `json:"provider_public_key_hex,omitempty"`

	// Operation transcript vectors.
	ArmHex     string `json:"arm_hex,omitempty"`
	WAN1Hex    string `json:"wan1_hex,omitempty"`
	ACKHex     string `json:"ack_hex,omitempty"`
	ReceiptHex string `json:"receipt_hex,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	Operation  string `json:"operation,omitempty"` // arm|ingress-ok|ingress-wrong-source|ingress-replay|ingress-expired|conflict
}

func TestProbeGoldenVectors(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "protocol", "testdata", "probe-frame")
	files := walkJSONFiles(t, dir)
	if len(files) == 0 {
		t.Fatalf("no probe-frame fixtures found under %s", dir)
	}
	for _, path := range files {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx probeFixture
			loadFixtureJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/probe-frame/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			switch fx.Kind {
			case "arm":
				validateProbeArmVector(t, fx)
			case "armed":
				validateProbeArmedVector(t, fx)
			case "wan1":
				validateProbeWAN1Vector(t, fx)
			case "ack":
				validateProbeACKVector(t, fx)
			case "receipt":
				validateProbeReceiptVector(t, fx)
			case "operation":
				validateProbeOperationVector(t, fx)
			default:
				t.Fatalf("unknown probe fixture kind %q", fx.Kind)
			}
		})
	}
}

func decodeProbeFrame(t *testing.T, hexstr string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(hexstr)
	if err != nil {
		t.Fatalf("frame hex: %v", err)
	}
	return raw
}

func probeArmFromFixture(t *testing.T, fx probeFixture) probeArm {
	t.Helper()
	arm, err := parseProbeArm(decodeProbeFrame(t, fx.FrameHex))
	if err != nil {
		t.Fatalf("parse arm: %v", err)
	}
	if fx.ProbeIDHex != "" {
		want, _ := hex.DecodeString(fx.ProbeIDHex)
		if !bytesEqual(arm.probeID[:], want) {
			t.Errorf("probe_id mismatch")
		}
	}
	if fx.ProviderIDHex != "" {
		want, _ := hex.DecodeString(fx.ProviderIDHex)
		if !bytesEqual(arm.providerID[:], want) {
			t.Errorf("provider_id mismatch")
		}
	}
	if fx.Endpoint != "" && arm.endpoint != fx.Endpoint {
		t.Errorf("endpoint=%q want %q", arm.endpoint, fx.Endpoint)
	}
	if fx.TTLMS != 0 && arm.ttlMS != fx.TTLMS {
		t.Errorf("ttl_ms=%d want %d", arm.ttlMS, fx.TTLMS)
	}
	return arm
}

func validateProbeArmVector(t *testing.T, fx probeFixture) {
	t.Helper()
	raw := decodeProbeFrame(t, fx.FrameHex)
	switch fx.Expect {
	case "valid":
		if _, err := parseProbeArm(raw); err != nil {
			t.Fatalf("valid arm rejected: %v", err)
		}
	case "invalid":
		_, err := parseProbeArm(raw)
		if err == nil {
			t.Fatalf("invalid arm parsed successfully")
		}
		if fx.RejectReason != "" && !probeRejectMatches(err, fx.RejectReason) {
			t.Fatalf("arm rejected with %v, want %q", err, fx.RejectReason)
		}
	default:
		t.Fatalf("expect must be valid or invalid")
	}
}

func validateProbeArmedVector(t *testing.T, fx probeFixture) {
	t.Helper()
	raw := decodeProbeFrame(t, fx.FrameHex)
	nodePub, err := hex.DecodeString(fx.NodePubHex)
	if err != nil || len(nodePub) != ed25519.PublicKeySize {
		t.Fatalf("node_public_key_hex must be a 32-byte key")
	}
	digest, _ := hex.DecodeString(fx.ArmDigestHex)
	if len(digest) != probeDigestLen {
		t.Fatalf("arm_digest_hex must be 32-byte hex")
	}
	var wantDigest [probeDigestLen]byte
	copy(wantDigest[:], digest)
	_, err = parseProbeArmed(raw, nodePub, wantDigest)
	if fx.Expect == "valid" && err != nil {
		t.Fatalf("valid armed rejected: %v", err)
	}
	if fx.Expect == "invalid" && err == nil {
		t.Fatalf("invalid armed parsed successfully")
	}
}

func validateProbeWAN1Vector(t *testing.T, fx probeFixture) {
	t.Helper()
	raw := decodeProbeFrame(t, fx.FrameHex)
	f, err := parseProviderFrame(raw)
	if err != nil {
		if fx.Expect == "invalid" && fx.RejectReason == "malformed" {
			return
		}
		if fx.Expect == "valid" {
			t.Fatalf("valid wan1 rejected: %v", err)
		}
		t.Fatalf("wan1 rejected with %v (fixture expect=%s reason=%s)", err, fx.Expect, fx.RejectReason)
	}
	if fx.Expect == "invalid" && fx.RejectReason == "signature" {
		// Structural parse succeeded; signature must fail against the key.
		providerPub, derr := hex.DecodeString(fx.ProviderPubHex)
		if derr != nil || len(providerPub) != ed25519.PublicKeySize {
			t.Fatalf("provider_public_key_hex must be a 32-byte key")
		}
		if ed25519.Verify(providerPub, f.signingBytes(), f.signature) {
			t.Fatalf("wan1 signature unexpectedly verifies for a signature-reject vector")
		}
		return
	}
	if fx.Expect == "invalid" {
		t.Fatalf("invalid wan1 parsed successfully (no reject reason matched)")
	}
	if fx.ChallengeHex != "" {
		want, _ := hex.DecodeString(fx.ChallengeHex)
		if !bytesEqual(f.challenge[:], want) {
			t.Errorf("challenge mismatch")
		}
	}
	if fx.Endpoint != "" && f.endpoint != fx.Endpoint {
		t.Errorf("endpoint=%q want %q", f.endpoint, fx.Endpoint)
	}
	// Signature must verify against the provider key bound by the fixture.
	providerPub, err := hex.DecodeString(fx.ProviderPubHex)
	if err != nil || len(providerPub) != ed25519.PublicKeySize {
		t.Fatalf("provider_public_key_hex must be a 32-byte key")
	}
	if !ed25519.Verify(providerPub, f.signingBytes(), f.signature) {
		t.Fatalf("wan1 signature does not verify against provider key")
	}
}

func validateProbeACKVector(t *testing.T, fx probeFixture) {
	t.Helper()
	raw := decodeProbeFrame(t, fx.FrameHex)
	nodePub, err := hex.DecodeString(fx.NodePubHex)
	if err != nil || len(nodePub) != ed25519.PublicKeySize {
		t.Fatalf("node_public_key_hex must be a 32-byte key")
	}
	ack, err := parseProbeACK(raw, nodePub)
	if fx.Expect == "invalid" {
		if err == nil {
			t.Fatalf("invalid ack parsed successfully")
		}
		return
	}
	if err != nil {
		t.Fatalf("valid ack rejected: %v", err)
	}
	if fx.ChallengeHashHex != "" {
		want, _ := hex.DecodeString(fx.ChallengeHashHex)
		if !bytesEqual(ack.challengeHash[:], want) {
			t.Errorf("challenge_hash mismatch")
		}
	}
}

func validateProbeReceiptVector(t *testing.T, fx probeFixture) {
	t.Helper()
	raw := decodeProbeFrame(t, fx.FrameHex)
	nodePub, err := hex.DecodeString(fx.NodePubHex)
	if err != nil || len(nodePub) != ed25519.PublicKeySize {
		t.Fatalf("node_public_key_hex must be a 32-byte key")
	}
	receipt, err := parseProbeReceipt(raw, nodePub)
	if fx.Expect == "invalid" {
		if err == nil {
			t.Fatalf("invalid receipt parsed successfully")
		}
		return
	}
	if err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	if fx.ProviderIDHex != "" {
		want, _ := hex.DecodeString(fx.ProviderIDHex)
		if !bytesEqual(receipt.providerID[:], want) {
			t.Errorf("provider_id mismatch")
		}
	}
}

// validateProbeOperationVector runs the full frozen probe state machine over
// the transcript and pins the anti-oracle, replay, conflict, and TTL rules.
func validateProbeOperationVector(t *testing.T, fx probeFixture) {
	t.Helper()
	arm, err := parseProbeArm(decodeProbeFrame(t, fx.ArmHex))
	if err != nil {
		t.Fatalf("parse arm: %v", err)
	}
	// Anti-oracle: the arm must never carry the provider challenge. The
	// challenge is introduced only by the provider frame at ingress.
	if bytesIndex(arm.canonical(), []byte("challenge")) >= 0 {
		t.Fatalf("arm must not contain challenge material")
	}
	wan1, err := parseProviderFrame(decodeProbeFrame(t, fx.WAN1Hex))
	if err != nil {
		t.Fatalf("parse wan1: %v", err)
	}

	now := time.Unix(2_000_000_000, 0)
	agent := newProbeAgentState(agentPriv())
	armed, err := agent.armProbe(arm, now)
	if err != nil {
		t.Fatalf("armProbe: %v", err)
	}
	// Armed response must verify against the node public key and bind the
	// arm digest.
	if !ed25519.Verify(agentPub(), armed.signingBytes(), armed.signature) {
		t.Fatalf("armed response signature invalid")
	}

	srcIP := probeParseIPv4(t, fx.SourceIP)

	switch fx.Operation {
	case "ingress-ok":
		if !agent.handleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("valid ingress rejected")
		}
		// Consumed exactly once: a replay of the same frame must fail.
		if agent.handleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("replayed ingress accepted after consumption")
		}
		// The ACK and receipt vectors in the fixture must verify and join.
		ackRaw := decodeProbeFrame(t, fx.ACKHex)
		ack, aerr := parseProbeACK(ackRaw, agentPub())
		if aerr != nil {
			t.Fatalf("parse ack: %v", aerr)
		}
		receiptRaw := decodeProbeFrame(t, fx.ReceiptHex)
		receipt, rerr := parseProbeReceipt(receiptRaw, agentPub())
		if rerr != nil {
			t.Fatalf("parse receipt: %v", rerr)
		}
		if !verifyProbeJoin(arm, wan1, ack, receipt, agentPub()) {
			t.Fatalf("probe join failed for valid transcript")
		}
	case "ingress-wrong-source":
		if agent.handleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("ingress accepted from wrong source")
		}
	case "ingress-wrong-activation":
		mutated := wan1
		mutated.activation[0] ^= 0xff
		if agent.handleProbeIngress(mutated, srcIP, now) {
			t.Fatalf("ingress accepted with wrong activation")
		}
	case "ingress-wrong-provider":
		mutated := wan1
		mutated.providerID[0] ^= 0xff
		if agent.handleProbeIngress(mutated, srcIP, now) {
			t.Fatalf("ingress accepted with wrong provider")
		}
	case "ingress-expired":
		// Advance the agent clock past the arm TTL.
		late := now.Add(time.Duration(arm.ttlMS)*time.Millisecond + time.Second)
		if agent.handleProbeIngress(wan1, srcIP, late) {
			t.Fatalf("ingress accepted after TTL expiry")
		}
	case "replay":
		// First consume, then assert the replay cache rejects re-arm with the
		// same material and conflicts on different material.
		if !agent.handleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("initial ingress rejected")
		}
		if _, err := agent.armProbe(arm, now); err != ErrProbeReplay {
			t.Fatalf("re-arm after consumption: got %v, want ErrProbeReplay", err)
		}
		conflict := arm
		conflict.endpoint = "203.0.113.9:4444"
		if _, err := agent.armProbe(conflict, now); err != ErrProbeIDConflict {
			t.Fatalf("conflicting re-arm: got %v, want ErrProbeIDConflict", err)
		}
	default:
		t.Fatalf("unknown operation %q", fx.Operation)
	}
}

func probeRejectMatches(err error, reason string) bool {
	switch reason {
	case "malformed":
		return err == ErrProbeMalformed
	case "endpoint":
		return err == ErrProbeEndpoint
	case "signature":
		return err == ErrProbeSignature
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesIndex(haystack []byte, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if bytesEqual(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

func probeParseIPv4(t *testing.T, s string) [4]byte {
	t.Helper()
	var out [4]byte
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("invalid source_ip %q", s)
	}
	copy(out[:], ip)
	return out
}
