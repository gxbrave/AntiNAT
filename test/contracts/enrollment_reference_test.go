package contracts

// Frozen AntiNAT enrollment transcript encoding (docs/protocol.md §3).
//
// Three canonical length-prefixed messages, each domain-separated and signed
// with Ed25519. All lengths big-endian. No JSON map serialization is
// permitted for the signed envelope; every message is the deterministic byte
// encoding below.
//
//   EnrollChallenge (controller -> agent, signed by the pinned controller key):
//     domain              "AntiNAT-Enroll-v1"
//     controller_instance_id 16 bytes
//     controller_key_id      utf8
//     node_id                16 bytes
//     server_nonce           32 bytes
//     protocol_versions      utf8 ("1")
//     expiry_unix            uint64 BE
//     signature              Ed25519 over domain || length-prefixed fields
//
//   EnrollRequest (agent -> controller, signed by the new agent key; the
//     signature is the possession proof):
//     domain              "AntiNAT-Enroll-v1"
//     challenge_hash         32 bytes  (sha256 of the canonical challenge)
//     agent_nonce            32 bytes
//     agent_public_key       32 bytes
//     agent_credential_version uint32 BE
//     token                  utf8, 1..256 bytes
//     capability_hash        32 bytes
//     signature              Ed25519 over domain || length-prefixed fields
//
//   EnrollResult (controller -> agent, signed by the controller signing key):
//     domain              "AntiNAT-Enroll-v1"
//     controller_instance_id 16 bytes
//     controller_key_id      utf8
//     node_id                16 bytes
//     agent_public_key_hash  32 bytes
//     agent_credential_version uint32 BE
//     enrollment_result_id   16 bytes
//     expiry_unix            uint64 BE
//     signature              Ed25519 over domain || length-prefixed fields

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

const (
	enrollDomain       = "AntiNAT-Enroll-v1"
	enrollVersion      = "1"
	maxTokenBytes      = 256
	enrollNonceSize    = 32
	enrollKeySize      = ed25519.PublicKeySize
	enrollHashSize     = sha256.Size
	enrollIDSize       = 16
	enrollSigLen       = ed25519.SignatureSize
	enrollChallengeMax = 4 + 16 + 255 + 16 + 32 + 64 + 8 + enrollSigLen
	enrollRequestMax   = 4 + 32 + 32 + 32 + 4 + maxTokenBytes + 32 + enrollSigLen
	enrollResultMax    = 4 + 16 + 255 + 16 + 32 + 4 + 16 + 8 + enrollSigLen
)

var (
	ErrEnrollSignature = errors.New("enrollment message has an invalid signature")
	ErrEnrollDomain    = errors.New("enrollment message domain mismatch")
	ErrEnrollChallenge = errors.New("enrollment request challenge hash mismatch")
	ErrEnrollMalformed = errors.New("enrollment message malformed")
	ErrEnrollDirection = errors.New("enrollment message signed by wrong side")
)

// enrollEncode renders a canonical length-prefixed field list.
func enrollEncode(fields ...[]byte) []byte {
	var buf bytes.Buffer
	for _, f := range fields {
		if len(f) > math.MaxUint32 {
			panic("enrollment field too large")
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		buf.Write(l[:])
		buf.Write(f)
	}
	return buf.Bytes()
}

func enrollU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func enrollU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// enrollSignatureInput is domain || canonical fields.
func enrollSignatureInput(domain string, fields []byte) []byte {
	return append([]byte(domain), fields...)
}

// ---------------------------------------------------------------------------
// EnrollChallenge
// ---------------------------------------------------------------------------

type enrollChallenge struct {
	controllerInstanceID [enrollIDSize]byte
	controllerKeyID      string
	nodeID               [enrollIDSize]byte
	serverNonce          [enrollNonceSize]byte
	protocolVersions     string
	expiryUnix           uint64
}

func (c enrollChallenge) canonical() []byte {
	return enrollEncode(
		c.controllerInstanceID[:],
		[]byte(c.controllerKeyID),
		c.nodeID[:],
		c.serverNonce[:],
		[]byte(c.protocolVersions),
		enrollU64(c.expiryUnix),
	)
}

func (c enrollChallenge) signingBytes() []byte {
	return enrollSignatureInput(enrollDomain, c.canonical())
}

// parseEnrollChallenge decodes and validates a signed EnrollChallenge.
func parseEnrollChallenge(raw []byte, controllerPub ed25519.PublicKey) (enrollChallenge, error) {
	var c enrollChallenge
	if len(raw) > enrollChallengeMax {
		return c, ErrEnrollMalformed
	}
	fields, sig, err := enrollSplit(raw)
	if err != nil {
		return c, err
	}
	parts, err := enrollReadFields(fields, 6)
	if err != nil {
		return c, err
	}
	copy(c.controllerInstanceID[:], parts[0])
	c.controllerKeyID = string(parts[1])
	copy(c.nodeID[:], parts[2])
	copy(c.serverNonce[:], parts[3])
	c.protocolVersions = string(parts[4])
	c.expiryUnix = binary.BigEndian.Uint64(parts[5])
	if len(parts[0]) != enrollIDSize || len(parts[2]) != enrollIDSize || len(parts[3]) != enrollNonceSize {
		return c, ErrEnrollMalformed
	}
	if c.protocolVersions != enrollVersion {
		return c, ErrEnrollMalformed
	}
	if err := c.verifySignature(controllerPub, sig); err != nil {
		return c, err
	}
	return c, nil
}

func (c enrollChallenge) verifySignature(pub ed25519.PublicKey, sig []byte) error {
	if !ed25519.Verify(pub, c.signingBytes(), sig) {
		return ErrEnrollSignature
	}
	return nil
}

// ---------------------------------------------------------------------------
// EnrollRequest
// ---------------------------------------------------------------------------

type enrollRequest struct {
	challengeHash          [enrollHashSize]byte
	agentNonce             [enrollNonceSize]byte
	agentPublicKey         [enrollKeySize]byte
	agentCredentialVersion uint32
	token                  string
	capabilityHash         [enrollHashSize]byte
}

func (r enrollRequest) canonical() []byte {
	return enrollEncode(
		r.challengeHash[:],
		r.agentNonce[:],
		r.agentPublicKey[:],
		enrollU32(r.agentCredentialVersion),
		[]byte(r.token),
		r.capabilityHash[:],
	)
}

func (r enrollRequest) signingBytes() []byte {
	return enrollSignatureInput(enrollDomain, r.canonical())
}

func (r enrollRequest) publicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), r.agentPublicKey[:]...)
}

// parseEnrollRequest decodes and validates a signed EnrollRequest against the
// exact challenge hash the server issued; the signature proves possession of
// the agent private key.
func parseEnrollRequest(raw []byte, challengeHash [enrollHashSize]byte) (enrollRequest, error) {
	var r enrollRequest
	if len(raw) > enrollRequestMax {
		return r, ErrEnrollMalformed
	}
	fields, sig, err := enrollSplit(raw)
	if err != nil {
		return r, err
	}
	parts, err := enrollReadFields(fields, 6)
	if err != nil {
		return r, err
	}
	copy(r.challengeHash[:], parts[0])
	copy(r.agentNonce[:], parts[1])
	copy(r.agentPublicKey[:], parts[2])
	r.agentCredentialVersion = binary.BigEndian.Uint32(parts[3])
	r.token = string(parts[4])
	copy(r.capabilityHash[:], parts[5])
	if len(parts[0]) != enrollHashSize || len(parts[1]) != enrollNonceSize || len(parts[2]) != enrollKeySize || len(parts[5]) != enrollHashSize {
		return r, ErrEnrollMalformed
	}
	if len(r.token) == 0 || len(r.token) > maxTokenBytes {
		return r, ErrEnrollMalformed
	}
	if r.agentCredentialVersion == 0 {
		return r, ErrEnrollMalformed
	}
	if !bytes.Equal(r.challengeHash[:], challengeHash[:]) {
		return r, ErrEnrollChallenge
	}
	if !ed25519.Verify(r.publicKey(), r.signingBytes(), sig) {
		return r, ErrEnrollSignature
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// EnrollResult
// ---------------------------------------------------------------------------

type enrollResult struct {
	controllerInstanceID   [enrollIDSize]byte
	controllerKeyID        string
	nodeID                 [enrollIDSize]byte
	agentPublicKeyHash     [enrollHashSize]byte
	agentCredentialVersion uint32
	enrollmentResultID     [enrollIDSize]byte
	expiryUnix             uint64
}

func (r enrollResult) canonical() []byte {
	return enrollEncode(
		r.controllerInstanceID[:],
		[]byte(r.controllerKeyID),
		r.nodeID[:],
		r.agentPublicKeyHash[:],
		enrollU32(r.agentCredentialVersion),
		r.enrollmentResultID[:],
		enrollU64(r.expiryUnix),
	)
}

func (r enrollResult) signingBytes() []byte {
	return enrollSignatureInput(enrollDomain, r.canonical())
}

func parseEnrollResult(raw []byte, controllerPub ed25519.PublicKey) (enrollResult, error) {
	var r enrollResult
	if len(raw) > enrollResultMax {
		return r, ErrEnrollMalformed
	}
	fields, sig, err := enrollSplit(raw)
	if err != nil {
		return r, err
	}
	parts, err := enrollReadFields(fields, 7)
	if err != nil {
		return r, err
	}
	copy(r.controllerInstanceID[:], parts[0])
	r.controllerKeyID = string(parts[1])
	copy(r.nodeID[:], parts[2])
	copy(r.agentPublicKeyHash[:], parts[3])
	r.agentCredentialVersion = binary.BigEndian.Uint32(parts[4])
	copy(r.enrollmentResultID[:], parts[5])
	r.expiryUnix = binary.BigEndian.Uint64(parts[6])
	if len(parts[0]) != enrollIDSize || len(parts[2]) != enrollIDSize || len(parts[3]) != enrollHashSize || len(parts[5]) != enrollIDSize {
		return r, ErrEnrollMalformed
	}
	if r.agentCredentialVersion == 0 {
		return r, ErrEnrollMalformed
	}
	if !ed25519.Verify(controllerPub, r.signingBytes(), sig) {
		return r, ErrEnrollSignature
	}
	return r, nil
}

// enrollSplit separates canonical fields from the trailing signature.
func enrollSplit(raw []byte) (fields, sig []byte, err error) {
	if len(raw) < enrollSigLen {
		return nil, nil, ErrEnrollMalformed
	}
	sig = append([]byte(nil), raw[len(raw)-enrollSigLen:]...)
	fields = raw[:len(raw)-enrollSigLen]
	if len(fields) == 0 {
		return nil, nil, ErrEnrollMalformed
	}
	return fields, sig, nil
}

// enrollReadFields parses count length-prefixed fields with full bounds checks.
func enrollReadFields(b []byte, count int) ([][]byte, error) {
	parts := make([][]byte, 0, count)
	idx := 0
	for i := 0; i < count; i++ {
		if len(b)-idx < 4 {
			return nil, ErrEnrollMalformed
		}
		l := binary.BigEndian.Uint32(b[idx : idx+4])
		idx += 4
		if uint64(l) > uint64(len(b)-idx) {
			return nil, ErrEnrollMalformed
		}
		parts = append(parts, b[idx:idx+int(l)])
		idx += int(l)
	}
	if idx != len(b) {
		return nil, ErrEnrollMalformed
	}
	return parts, nil
}

// ---------------------------------------------------------------------------
// Deterministic TEST-ONLY signing helpers (published fixture keys, never real
// credentials).
// ---------------------------------------------------------------------------

func signEnrollChallenge(c enrollChallenge, priv ed25519.PrivateKey) []byte {
	return append(c.canonical(), ed25519.Sign(priv, c.signingBytes())...)
}

func signEnrollRequest(r enrollRequest, priv ed25519.PrivateKey) []byte {
	return append(r.canonical(), ed25519.Sign(priv, r.signingBytes())...)
}

func signEnrollResult(r enrollResult, priv ed25519.PrivateKey) []byte {
	return append(r.canonical(), ed25519.Sign(priv, r.signingBytes())...)
}

func enrollChallengeHash(c enrollChallenge) [enrollHashSize]byte {
	return sha256.Sum256(c.canonical())
}
