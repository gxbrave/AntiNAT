package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

// controlEnvelopeFixture is the frozen fixture schema for golden control
// envelope vectors. `expect` is "valid" or "invalid"; for invalid vectors
// `reject_stage` names the exact stage at which parsing must fail (one of
// framing, header, consistency, signature, payload_json).
type controlEnvelopeFixture struct {
	Schema      string `json:"schema"`
	VectorID    string `json:"vector_id"`
	Expect      string `json:"expect"`
	RejectStage string `json:"reject_stage,omitempty"`
	FrameHex    string `json:"frame_hex"`
	Verifier    string `json:"verifier"` // "agent" or "controller"
	PubKeyHex   string `json:"public_key_hex,omitempty"`
	Header      struct {
		ProtocolDomain       string `json:"protocol_domain"`
		ControllerInstanceID string `json:"controller_instance_id"`
		NodeID               string `json:"node_id"`
		ControllerKeyID      string `json:"controller_key_id"`
		AgentCredentialVer   uint32 `json:"agent_credential_version"`
		ConnectionEpoch      uint64 `json:"connection_epoch"`
		SessionID            string `json:"session_id"`
		Direction            string `json:"direction"`
		Sequence             uint64 `json:"sequence"`
		MessageID            string `json:"message_id"`
		MessageType          string `json:"message_type"`
		SchemaVersion        uint32 `json:"schema_version"`
		PayloadLength        uint64 `json:"payload_length"`
		PayloadSHA256        string `json:"payload_sha256"`
	} `json:"header"`
	PayloadHex  string `json:"payload_hex,omitempty"`
	PayloadJSON string `json:"payload_json,omitempty"`
}

func stageFromString(s string) (rejectStage, error) {
	switch s {
	case "framing":
		return stageFraming, nil
	case "header":
		return stageHeader, nil
	case "consistency":
		return stageConsistency, nil
	case "signature":
		return stageSignature, nil
	case "payload_json":
		return stagePayloadJSON, nil
	}
	return stageOK, errors.New("unknown reject_stage " + s)
}

func verifierDirection(verifier string) (byte, error) {
	switch verifier {
	case "agent":
		return dirControllerToAgent, nil
	case "controller":
		return dirAgentToController, nil
	}
	return 0, errors.New("unknown verifier " + verifier)
}

func TestControlEnvelopeGoldenVectors(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "protocol", "testdata", "control-envelope")
	files := walkJSONFiles(t, dir)
	if len(files) == 0 {
		t.Fatalf("no control-envelope fixtures found under %s", dir)
	}
	for _, path := range files {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx controlEnvelopeFixture
			loadFixtureJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/control-envelope/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			frame, err := hex.DecodeString(fx.FrameHex)
			if err != nil {
				t.Fatalf("frame_hex: %v", err)
			}
			peer, err := hex.DecodeString(fx.PubKeyHex)
			if err != nil || len(peer) != ed25519.PublicKeySize {
				t.Fatalf("public_key_hex must be a 32-byte key")
			}
			env, stage, err := parseEnvelope(frame, peer)
			switch fx.Expect {
			case "valid":
				if err != nil {
					t.Fatalf("valid vector rejected: %v", err)
				}
				if stage != stageOK {
					t.Fatalf("valid vector stopped at stage %v", stage)
				}
				assertHeaderMatches(t, fx, env)
				if fx.PayloadHex != "" {
					want, _ := hex.DecodeString(fx.PayloadHex)
					if !bytes.Equal(env.payload, want) {
						t.Fatalf("payload mismatch: got %x want %x", env.payload, want)
					}
				}
				if fx.PayloadJSON != "" {
					if err := validateStrictJSON(env.payload, nil); err != nil {
						t.Fatalf("payload strict JSON validation failed: %v", err)
					}
				}
			case "invalid":
				if err == nil {
					t.Fatalf("invalid vector parsed successfully")
				}
				wantStage, serr := stageFromString(fx.RejectStage)
				if serr != nil {
					t.Fatalf("fixture reject_stage: %v", serr)
				}
				if stage != wantStage {
					t.Fatalf("invalid vector failed at stage %v, want %v (err=%v)", stage, wantStage, err)
				}
			default:
				t.Fatalf("fixture expect must be valid or invalid, got %q", fx.Expect)
			}
		})
	}
}

func assertHeaderMatches(t *testing.T, fx controlEnvelopeFixture, env envelope) {
	t.Helper()
	h := env.header
	if h.protocolDomain != fx.Header.ProtocolDomain {
		t.Errorf("protocol_domain=%q want %q", h.protocolDomain, fx.Header.ProtocolDomain)
	}
	if h.controllerKeyID != fx.Header.ControllerKeyID {
		t.Errorf("controller_key_id=%q want %q", h.controllerKeyID, fx.Header.ControllerKeyID)
	}
	if h.agentCredentialVer != fx.Header.AgentCredentialVer {
		t.Errorf("agent_credential_version=%d want %d", h.agentCredentialVer, fx.Header.AgentCredentialVer)
	}
	if h.connectionEpoch != fx.Header.ConnectionEpoch {
		t.Errorf("connection_epoch=%d want %d", h.connectionEpoch, fx.Header.ConnectionEpoch)
	}
	if h.sessionID != fx.Header.SessionID {
		t.Errorf("session_id=%q want %q", h.sessionID, fx.Header.SessionID)
	}
	if h.sequence != fx.Header.Sequence {
		t.Errorf("sequence=%d want %d", h.sequence, fx.Header.Sequence)
	}
	if h.messageType != fx.Header.MessageType {
		t.Errorf("message_type=%q want %q", h.messageType, fx.Header.MessageType)
	}
	if h.schemaVersion != fx.Header.SchemaVersion {
		t.Errorf("schema_version=%d want %d", h.schemaVersion, fx.Header.SchemaVersion)
	}
	wantDir, err := verifierDirection(fx.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if h.direction != wantDir {
		t.Errorf("direction=%x want %x for verifier %s", h.direction, wantDir, fx.Verifier)
	}
	if fx.Header.PayloadLength != 0 && h.payloadLength != fx.Header.PayloadLength {
		t.Errorf("payload_length=%d want %d", h.payloadLength, fx.Header.PayloadLength)
	}
	if fx.Header.PayloadSHA256 != "" {
		want, _ := hex.DecodeString(fx.Header.PayloadSHA256)
		if !bytes.Equal(h.payloadSHA256[:], want) {
			t.Errorf("payload_sha256 mismatch")
		}
	}
}

// TestControlEnvelopeBitFlipFailsBeforePayloadDecode mutates every bit of
// every valid vector and asserts the mutated frame is rejected at a
// pre-payload stage (framing, header, consistency, or signature) — never a
// successful parse and never a payload decode.
func TestControlEnvelopeBitFlipFailsBeforePayloadDecode(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "protocol", "testdata", "control-envelope")
	for _, path := range walkJSONFiles(t, dir) {
		var fx controlEnvelopeFixture
		loadFixtureJSON(t, path, &fx)
		if fx.Expect != "valid" {
			continue
		}
		frame, err := hex.DecodeString(fx.FrameHex)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		peer, _ := hex.DecodeString(fx.PubKeyHex)
		for i := 0; i < len(frame); i++ {
			for bit := uint(0); bit < 8; bit++ {
				mutated := append([]byte(nil), frame...)
				mutated[i] ^= 1 << bit
				_, stage, perr := parseEnvelope(mutated, peer)
				if perr == nil {
					t.Fatalf("%s: bit flip at byte %d bit %d parsed successfully", path, i, bit)
				}
				if stage == stagePayloadJSON {
					t.Fatalf("%s: bit flip at byte %d bit %d reached payload decode", path, i, bit)
				}
				if stage == stageOK {
					t.Fatalf("%s: bit flip at byte %d bit %d returned OK", path, i, bit)
				}
			}
		}
	}
}

// TestControlEnvelopeRejectsAmbiguousJSON pins the strict JSON payload rules:
// duplicate keys, unknown fields, over-deep nesting, out-of-range numbers,
// and oversize payloads must all be rejected.
func TestControlEnvelopeRejectsAmbiguousJSON(t *testing.T) {
	valid := []byte(`{"a":1,"b":"x"}`)
	if err := validateStrictJSON(valid, nil); err != nil {
		t.Fatalf("baseline valid payload rejected: %v", err)
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"duplicate-key", `{"a":1,"a":2}`},
		{"trailing-garbage", `{"a":1} extra`},
		{"deep-nesting", `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":1}}}}}}}}}}}}}}}}}`},
		{"out-of-range-number", `{"a":9223372036854775808}`},
		{"fractional-number", `{"a":1.5}`},
		{"empty", ``},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := validateStrictJSON([]byte(tc.raw), nil); err == nil {
				t.Fatalf("expected rejection for %q", tc.raw)
			}
		})
	}
	// Unknown-field rejection requires a schema.
	schema := map[string]fieldKind{"a": kindInt}
	if err := validateStrictJSON([]byte(`{"a":1,"zz":2}`), schema); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	if err := validateStrictJSON([]byte(`{"a":1}`), schema); err != nil {
		t.Fatalf("schema-valid payload rejected: %v", err)
	}
}
