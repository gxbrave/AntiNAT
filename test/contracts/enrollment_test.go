package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// enrollmentFixture is the frozen fixture schema for golden enrollment
// transcript vectors. `kind` is one of "challenge", "request", "result";
// `expect` is "valid" or "invalid"; for invalid vectors `reject_reason`
// names the exact failure (malformed, domain, challenge, signature).
type enrollmentFixture struct {
	Schema       string `json:"schema"`
	VectorID     string `json:"vector_id"`
	Kind         string `json:"kind"`
	Expect       string `json:"expect"`
	RejectReason string `json:"reject_reason,omitempty"`
	MsgHex       string `json:"message_hex"`
	// For requests: the expected challenge hash (hex) the request must bind.
	ChallengeHash string `json:"challenge_hash,omitempty"`
	// Verifier public key (hex). For challenge/result: controller pinned key.
	// For request: the agent key used to sign (verified against itself).
	PubKeyHex string `json:"public_key_hex,omitempty"`
	// Optional semantic fields checked on valid vectors.
	ControllerKeyID        string `json:"controller_key_id,omitempty"`
	ProtocolVersions       string `json:"protocol_versions,omitempty"`
	AgentCredentialVersion uint32 `json:"agent_credential_version,omitempty"`
}

func TestEnrollmentGoldenVectors(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "protocol", "testdata", "enrollment")
	files := walkJSONFiles(t, dir)
	if len(files) == 0 {
		t.Fatalf("no enrollment fixtures found under %s", dir)
	}
	for _, path := range files {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx enrollmentFixture
			loadFixtureJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/enrollment/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			raw, err := hex.DecodeString(fx.MsgHex)
			if err != nil {
				t.Fatalf("message_hex: %v", err)
			}
			switch fx.Expect {
			case "valid":
				validateEnrollmentValid(t, fx, raw)
			case "invalid":
				validateEnrollmentInvalid(t, fx, raw)
			default:
				t.Fatalf("fixture expect must be valid or invalid, got %q", fx.Expect)
			}
		})
	}
}

func validateEnrollmentValid(t *testing.T, fx enrollmentFixture, raw []byte) {
	t.Helper()
	switch fx.Kind {
	case "challenge":
		pub, err := hex.DecodeString(fx.PubKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("public_key_hex must be a 32-byte key")
		}
		c, err := parseEnrollChallenge(raw, pub)
		if err != nil {
			t.Fatalf("valid challenge rejected: %v", err)
		}
		if fx.ControllerKeyID != "" && c.controllerKeyID != fx.ControllerKeyID {
			t.Errorf("controller_key_id=%q want %q", c.controllerKeyID, fx.ControllerKeyID)
		}
		if fx.ProtocolVersions != "" && c.protocolVersions != fx.ProtocolVersions {
			t.Errorf("protocol_versions=%q want %q", c.protocolVersions, fx.ProtocolVersions)
		}
	case "request":
		ch, err := hex.DecodeString(fx.ChallengeHash)
		if err != nil || len(ch) != enrollHashSize {
			t.Fatalf("challenge_hash must be 32-byte hex")
		}
		var wantHash [enrollHashSize]byte
		copy(wantHash[:], ch)
		r, err := parseEnrollRequest(raw, wantHash)
		if err != nil {
			t.Fatalf("valid request rejected: %v", err)
		}
		if fx.AgentCredentialVersion != 0 && r.agentCredentialVersion != fx.AgentCredentialVersion {
			t.Errorf("agent_credential_version=%d want %d", r.agentCredentialVersion, fx.AgentCredentialVersion)
		}
	case "result":
		pub, err := hex.DecodeString(fx.PubKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("public_key_hex must be a 32-byte key")
		}
		r, err := parseEnrollResult(raw, pub)
		if err != nil {
			t.Fatalf("valid result rejected: %v", err)
		}
		if fx.ControllerKeyID != "" && r.controllerKeyID != fx.ControllerKeyID {
			t.Errorf("controller_key_id=%q want %q", r.controllerKeyID, fx.ControllerKeyID)
		}
	default:
		t.Fatalf("unknown enrollment kind %q", fx.Kind)
	}
}

func validateEnrollmentInvalid(t *testing.T, fx enrollmentFixture, raw []byte) {
	t.Helper()
	var err error
	switch fx.Kind {
	case "challenge":
		pub, derr := hex.DecodeString(fx.PubKeyHex)
		if derr != nil {
			t.Fatalf("public_key_hex: %v", derr)
		}
		_, err = parseEnrollChallenge(raw, pub)
	case "request":
		ch, derr := hex.DecodeString(fx.ChallengeHash)
		if derr != nil {
			t.Fatalf("challenge_hash: %v", derr)
		}
		var wantHash [enrollHashSize]byte
		copy(wantHash[:], ch)
		_, err = parseEnrollRequest(raw, wantHash)
	case "result":
		pub, derr := hex.DecodeString(fx.PubKeyHex)
		if derr != nil {
			t.Fatalf("public_key_hex: %v", derr)
		}
		_, err = parseEnrollResult(raw, pub)
	default:
		t.Fatalf("unknown enrollment kind %q", fx.Kind)
	}
	if err == nil {
		t.Fatalf("invalid %s vector parsed successfully", fx.Kind)
	}
	if fx.RejectReason != "" && !enrollRejectMatches(err, fx.RejectReason) {
		t.Fatalf("invalid vector rejected with %v, want reason %q", err, fx.RejectReason)
	}
}

func enrollRejectMatches(err error, reason string) bool {
	switch reason {
	case "malformed":
		return err == ErrEnrollMalformed
	case "domain":
		return err == ErrEnrollDomain
	case "challenge":
		return err == ErrEnrollChallenge
	case "signature":
		return err == ErrEnrollSignature
	}
	return true
}

// TestEnrollmentBitFlipFailsBeforeSemanticUse mutates every bit of every
// valid enrollment vector and asserts rejection (signed messages must never
// be accepted after any single-bit mutation).
func TestEnrollmentBitFlipFailsBeforeSemanticUse(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "protocol", "testdata", "enrollment")
	for _, path := range walkJSONFiles(t, dir) {
		var fx enrollmentFixture
		loadFixtureJSON(t, path, &fx)
		if fx.Expect != "valid" {
			continue
		}
		raw, err := hex.DecodeString(fx.MsgHex)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for i := 0; i < len(raw); i++ {
			for bit := uint(0); bit < 8; bit++ {
				mutated := append([]byte(nil), raw...)
				mutated[i] ^= 1 << bit
				var verr error
				switch fx.Kind {
				case "challenge":
					pub, _ := hex.DecodeString(fx.PubKeyHex)
					_, verr = parseEnrollChallenge(mutated, pub)
				case "request":
					ch, _ := hex.DecodeString(fx.ChallengeHash)
					var wantHash [enrollHashSize]byte
					copy(wantHash[:], ch)
					_, verr = parseEnrollRequest(mutated, wantHash)
				case "result":
					pub, _ := hex.DecodeString(fx.PubKeyHex)
					_, verr = parseEnrollResult(mutated, pub)
				}
				if verr == nil {
					t.Fatalf("%s: bit flip at byte %d bit %d parsed successfully", path, i, bit)
				}
			}
		}
	}
}
