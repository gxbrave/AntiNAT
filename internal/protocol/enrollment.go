// Enrollment transcript codec (docs/protocol.md §4). Three canonical
// length-prefixed messages, each domain-separated and signed with Ed25519.
// No JSON map serialization is permitted for the signed transcript.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/gxbrave/AntiNAT/internal/security/framecrypto"
)

// Enrollment domain and size constants frozen by docs/protocol.md §4.
const (
	EnrollDomain       = "AntiNAT-Enroll-v1"
	EnrollVersion      = "1"
	MaxTokenBytes      = 256
	EnrollNonceSize    = 32
	EnrollKeySize      = ed25519.PublicKeySize
	EnrollHashSize     = sha256.Size
	EnrollIDSize       = 16
	EnrollSigLen       = ed25519.SignatureSize
	EnrollChallengeMax = 4 + 16 + 255 + 16 + 32 + 64 + 8 + EnrollSigLen
	EnrollRequestMax   = 4 + 32 + 32 + 32 + 4 + MaxTokenBytes + 32 + EnrollSigLen
	EnrollResultMax    = 4 + 16 + 255 + 16 + 32 + 4 + 16 + 8 + EnrollSigLen
)

// Stable enrollment rejection reasons.
var (
	ErrEnrollSignature = errors.New("protocol: enrollment message has an invalid signature")
	ErrEnrollDomain    = errors.New("protocol: enrollment message domain mismatch")
	ErrEnrollChallenge = errors.New("protocol: enrollment request challenge hash mismatch")
	ErrEnrollMalformed = errors.New("protocol: enrollment message malformed")
	ErrEnrollDirection = errors.New("protocol: enrollment message signed by wrong side")
)

// enrollEncode renders a canonical length-prefixed field list (uint32 BE
// length + raw bytes).
func enrollEncode(fields ...[]byte) []byte {
	var buf bytes.Buffer
	for _, f := range fields {
		if len(f) > math.MaxUint32 {
			panic("protocol: enrollment field too large")
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
	return framecrypto.DomainSeparatedMessage(domain, fields)
}

// ---------------------------------------------------------------------------
// EnrollChallenge
// ---------------------------------------------------------------------------

// EnrollChallenge is the Controller→Agent signed challenge
// (docs/protocol.md §4.1).
type EnrollChallenge struct {
	ControllerInstanceID [EnrollIDSize]byte
	ControllerKeyID      string
	NodeID               [EnrollIDSize]byte
	ServerNonce          [EnrollNonceSize]byte
	ProtocolVersions     string
	ExpiryUnix           uint64
}

// Canonical renders the length-prefixed field list.
func (c EnrollChallenge) Canonical() []byte {
	return enrollEncode(
		c.ControllerInstanceID[:],
		[]byte(c.ControllerKeyID),
		c.NodeID[:],
		c.ServerNonce[:],
		[]byte(c.ProtocolVersions),
		enrollU64(c.ExpiryUnix),
	)
}

// SigningBytes is domain || canonical fields.
func (c EnrollChallenge) SigningBytes() []byte {
	return enrollSignatureInput(EnrollDomain, c.Canonical())
}

// ParseEnrollChallenge decodes and validates a signed EnrollChallenge against
// the pinned Controller public key.
func ParseEnrollChallenge(raw []byte, controllerPub ed25519.PublicKey) (EnrollChallenge, error) {
	var c EnrollChallenge
	if len(raw) > EnrollChallengeMax {
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
	copy(c.ControllerInstanceID[:], parts[0])
	c.ControllerKeyID = string(parts[1])
	copy(c.NodeID[:], parts[2])
	copy(c.ServerNonce[:], parts[3])
	c.ProtocolVersions = string(parts[4])
	c.ExpiryUnix = binary.BigEndian.Uint64(parts[5])
	if len(parts[0]) != EnrollIDSize || len(parts[2]) != EnrollIDSize || len(parts[3]) != EnrollNonceSize {
		return c, ErrEnrollMalformed
	}
	if c.ProtocolVersions != EnrollVersion {
		return c, ErrEnrollMalformed
	}
	if !framecrypto.Verify(controllerPub, c.SigningBytes(), sig) {
		return c, ErrEnrollSignature
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// EnrollRequest
// ---------------------------------------------------------------------------

// EnrollRequest is the Agent→Controller signed possession proof
// (docs/protocol.md §4.2).
type EnrollRequest struct {
	ChallengeHash          [EnrollHashSize]byte
	AgentNonce             [EnrollNonceSize]byte
	AgentPublicKey         [EnrollKeySize]byte
	AgentCredentialVersion uint32
	Token                  string
	CapabilityHash         [EnrollHashSize]byte
}

// Canonical renders the length-prefixed field list.
func (r EnrollRequest) Canonical() []byte {
	return enrollEncode(
		r.ChallengeHash[:],
		r.AgentNonce[:],
		r.AgentPublicKey[:],
		enrollU32(r.AgentCredentialVersion),
		[]byte(r.Token),
		r.CapabilityHash[:],
	)
}

// SigningBytes is domain || canonical fields.
func (r EnrollRequest) SigningBytes() []byte {
	return enrollSignatureInput(EnrollDomain, r.Canonical())
}

// PublicKey returns the presented agent public key.
func (r EnrollRequest) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), r.AgentPublicKey[:]...)
}

// ParseEnrollRequest decodes and validates a signed EnrollRequest against the
// exact challenge hash the server issued; the signature proves possession of
// the agent private key.
func ParseEnrollRequest(raw []byte, challengeHash [EnrollHashSize]byte) (EnrollRequest, error) {
	var r EnrollRequest
	if len(raw) > EnrollRequestMax {
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
	copy(r.ChallengeHash[:], parts[0])
	copy(r.AgentNonce[:], parts[1])
	copy(r.AgentPublicKey[:], parts[2])
	r.AgentCredentialVersion = binary.BigEndian.Uint32(parts[3])
	r.Token = string(parts[4])
	copy(r.CapabilityHash[:], parts[5])
	if len(parts[0]) != EnrollHashSize || len(parts[1]) != EnrollNonceSize ||
		len(parts[2]) != EnrollKeySize || len(parts[5]) != EnrollHashSize {
		return r, ErrEnrollMalformed
	}
	if len(r.Token) == 0 || len(r.Token) > MaxTokenBytes {
		return r, ErrEnrollMalformed
	}
	if r.AgentCredentialVersion == 0 {
		return r, ErrEnrollMalformed
	}
	if !bytes.Equal(r.ChallengeHash[:], challengeHash[:]) {
		return r, ErrEnrollChallenge
	}
	if !framecrypto.Verify(r.PublicKey(), r.SigningBytes(), sig) {
		return r, ErrEnrollSignature
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// EnrollResult
// ---------------------------------------------------------------------------

// EnrollResult is the Controller→Agent signed binding result
// (docs/protocol.md §4.3).
type EnrollResult struct {
	ControllerInstanceID   [EnrollIDSize]byte
	ControllerKeyID        string
	NodeID                 [EnrollIDSize]byte
	AgentPublicKeyHash     [EnrollHashSize]byte
	AgentCredentialVersion uint32
	EnrollmentResultID     [EnrollIDSize]byte
	ExpiryUnix             uint64
}

// Canonical renders the length-prefixed field list.
func (r EnrollResult) Canonical() []byte {
	return enrollEncode(
		r.ControllerInstanceID[:],
		[]byte(r.ControllerKeyID),
		r.NodeID[:],
		r.AgentPublicKeyHash[:],
		enrollU32(r.AgentCredentialVersion),
		r.EnrollmentResultID[:],
		enrollU64(r.ExpiryUnix),
	)
}

// SigningBytes is domain || canonical fields.
func (r EnrollResult) SigningBytes() []byte {
	return enrollSignatureInput(EnrollDomain, r.Canonical())
}

// ParseEnrollResult decodes and validates a signed EnrollResult against the
// Controller signing key.
func ParseEnrollResult(raw []byte, controllerPub ed25519.PublicKey) (EnrollResult, error) {
	var r EnrollResult
	if len(raw) > EnrollResultMax {
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
	copy(r.ControllerInstanceID[:], parts[0])
	r.ControllerKeyID = string(parts[1])
	copy(r.NodeID[:], parts[2])
	copy(r.AgentPublicKeyHash[:], parts[3])
	r.AgentCredentialVersion = binary.BigEndian.Uint32(parts[4])
	copy(r.EnrollmentResultID[:], parts[5])
	r.ExpiryUnix = binary.BigEndian.Uint64(parts[6])
	if len(parts[0]) != EnrollIDSize || len(parts[2]) != EnrollIDSize ||
		len(parts[3]) != EnrollHashSize || len(parts[5]) != EnrollIDSize {
		return r, ErrEnrollMalformed
	}
	if r.AgentCredentialVersion == 0 {
		return r, ErrEnrollMalformed
	}
	if !framecrypto.Verify(controllerPub, r.SigningBytes(), sig) {
		return r, ErrEnrollSignature
	}
	return r, nil
}

// enrollSplit separates canonical fields from the trailing signature.
func enrollSplit(raw []byte) (fields, sig []byte, err error) {
	if len(raw) < EnrollSigLen {
		return nil, nil, ErrEnrollMalformed
	}
	sig = append([]byte(nil), raw[len(raw)-EnrollSigLen:]...)
	fields = raw[:len(raw)-EnrollSigLen]
	if len(fields) == 0 {
		return nil, nil, ErrEnrollMalformed
	}
	return fields, sig, nil
}

// enrollReadFields parses count length-prefixed fields with full bounds
// checks and rejects trailing bytes.
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
