package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Story 3 two-sided signed-command prototype. Distinct Controller and Agent
// stores exchange domain-separated Ed25519 envelopes over a canonical binary
// protected header (never a JSON map), so stale signed commands are rejected
// on both sides and tampered, wrong-key, wrong-direction, and replayed
// envelopes fail closed before any inbox/outbox mutation.

const (
	// ProtocolDomain is the normative anti-catastrophe domain string.
	ProtocolDomain = "AntiNAT-Control-v1"
	// DirectionControllerToAgent marks a command from the Controller to the
	// Agent side.
	DirectionControllerToAgent = "controller_to_agent"
	// DirectionAgentToController marks an ACK/result from the Agent to the
	// Controller side.
	DirectionAgentToController = "agent_to_controller"
)

var (
	ErrInvalidSignature = errors.New("signed command has an invalid signature")
	ErrWrongDirection   = errors.New("signed command direction does not match the receiving side")
	ErrTamperedPayload  = errors.New("signed command payload does not match the signed payload hash")
)

// SignedMessage is a canonical protected header plus an Ed25519 signature.
// The signature covers protocol_domain, direction, epoch, session id,
// sequence, message id, message type, and payload sha-256 in a fixed binary
// encoding; the payload itself is authenticated through its hash.
type SignedMessage struct {
	ProtocolDomain string
	KeyID          string
	Direction      string
	Epoch          uint64
	SessionID      string
	Sequence       uint64
	MessageID      string
	MessageType    string
	PayloadHash    string
	Payload        string
	Signature      []byte
}

// NewSignedMessage builds an unsigned envelope, hashing the payload.
func NewSignedMessage(direction string, epoch uint64, sessionID string, sequence uint64, messageID, messageType, payload string) *SignedMessage {
	return &SignedMessage{
		ProtocolDomain: ProtocolDomain,
		KeyID:          "key-1",
		Direction:      direction,
		Epoch:          epoch,
		SessionID:      sessionID,
		Sequence:       sequence,
		MessageID:      messageID,
		MessageType:    messageType,
		PayloadHash:    hex.EncodeToString(hashBytes([]byte(payload))),
		Payload:        payload,
	}
}

func hashBytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func appendLengthPrefixed(dst []byte, parts ...[]byte) []byte {
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		dst = append(dst, length[:]...)
		dst = append(dst, part...)
	}
	return dst
}

// Canonical returns the deterministic binary protected header that is signed.
func (m *SignedMessage) Canonical() []byte {
	var epochBytes, sequenceBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], m.Epoch)
	binary.BigEndian.PutUint64(sequenceBytes[:], m.Sequence)
	return appendLengthPrefixed(nil,
		[]byte(m.ProtocolDomain),
		[]byte(m.KeyID),
		[]byte(m.Direction),
		epochBytes[:],
		[]byte(m.SessionID),
		sequenceBytes[:],
		[]byte(m.MessageID),
		[]byte(m.MessageType),
		[]byte(m.PayloadHash),
	)
}

// Sign signs the canonical protected header with the given private key.
func (m *SignedMessage) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key size %d", len(privateKey))
	}
	m.Signature = ed25519.Sign(privateKey, m.Canonical())
	return nil
}

// VerifySignature checks the domain, canonical header, and Ed25519 signature.
func (m *SignedMessage) VerifySignature(publicKey ed25519.PublicKey) error {
	if m.ProtocolDomain != ProtocolDomain {
		return fmt.Errorf("%w: domain %q", ErrInvalidSignature, m.ProtocolDomain)
	}
	if !ed25519.Verify(publicKey, m.Canonical(), m.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyForSide binds the envelope to a receiving side: the signature must be
// valid for the pinned peer key and the direction must match the side.
func (m *SignedMessage) VerifyForSide(peerPublicKey ed25519.PublicKey, expectedDirection string) error {
	if m.Direction != expectedDirection {
		return fmt.Errorf("%w: direction %q, want %q", ErrWrongDirection, m.Direction, expectedDirection)
	}
	if err := m.VerifySignature(peerPublicKey); err != nil {
		return err
	}
	if actual := hex.EncodeToString(hashBytes([]byte(m.Payload))); actual != m.PayloadHash {
		return fmt.Errorf("%w: hash %q, want %q", ErrTamperedPayload, actual, m.PayloadHash)
	}
	return nil
}

// DeliverSigned verifies a signed envelope against the pinned peer key and the
// receiving side's direction, then enters it into the store's inbox with
// epoch/session fencing and message-id deduplication. It returns whether the
// message was an identical duplicate.
func DeliverSigned(store *Store, peerPublicKey ed25519.PublicKey, expectedDirection string, message *SignedMessage) (bool, error) {
	if err := message.VerifyForSide(peerPublicKey, expectedDirection); err != nil {
		return false, err
	}
	return store.ReceiveCommand(message.Epoch, message.SessionID, message.MessageID, message.MessageType, message.PayloadHash)
}
