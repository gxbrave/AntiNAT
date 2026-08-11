package network

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	ErrInvalidEd25519Key = errors.New("invalid Ed25519 key")
	ErrProbeReplay       = errors.New("probe ID is in the replay cache")
	ErrProbeIDConflict   = errors.New("probe ID is already armed with different material")
	ErrProbeStateFull    = errors.New("probe state capacity exhausted")
	ErrMalformedFrame    = errors.New("malformed provider frame")
)

const (
	defaultProbeOperations = 256
	defaultProbeReplay     = 512
	probeReplayWindow      = 5 * time.Minute
	providerFrameMax       = 4 + 32 + 16 + 16 + 16 + 1 + 255 + 16 + 32 + ed25519.SignatureSize
)

type ProbeArm struct {
	ProbeID           [16]byte
	ProviderID        [16]byte
	ProviderPublicKey ed25519.PublicKey
	ExpectedSourceIP  [4]byte
	Activation        [16]byte
	Endpoint          string
	TTL               time.Duration
	ExpiryOpaque      [16]byte
}

func (arm ProbeArm) MarshalBinary() ([]byte, error) {
	if len(arm.ProviderPublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidEd25519Key
	}
	if arm.TTL <= 0 || arm.TTL > 24*time.Hour || validateEndpoint(arm.Endpoint) != nil {
		return nil, errors.New("arm requires a bounded TTL and concrete endpoint")
	}
	endpoint := []byte(arm.Endpoint)
	buffer := bytes.NewBuffer(make([]byte, 0, 4+16+16+32+4+16+1+len(endpoint)+8+16))
	buffer.WriteString("ARM1")
	buffer.Write(arm.ProbeID[:])
	buffer.Write(arm.ProviderID[:])
	buffer.Write(arm.ProviderPublicKey)
	buffer.Write(arm.ExpectedSourceIP[:])
	buffer.Write(arm.Activation[:])
	buffer.WriteByte(byte(len(endpoint)))
	buffer.Write(endpoint)
	var ttl [8]byte
	binary.BigEndian.PutUint64(ttl[:], uint64(arm.TTL))
	buffer.Write(ttl[:])
	buffer.Write(arm.ExpiryOpaque[:])
	return buffer.Bytes(), nil
}

type ProbeArmed struct {
	ArmDigest [32]byte
	Signature []byte
}

type ProbeOutcome string

const (
	ProbeAccepted ProbeOutcome = "ACCEPTED"
	ProbeRejected ProbeOutcome = "REJECTED"
)

type ProviderFrame struct {
	ArmDigest    [32]byte
	ProbeID      [16]byte
	ProviderID   [16]byte
	Activation   [16]byte
	Endpoint     string
	ExpiryOpaque [16]byte
	Challenge    [32]byte
	Signature    []byte
}

func (frame ProviderFrame) signingBytes() []byte {
	if len(frame.Endpoint) > 255 {
		return nil
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 4+32+16+16+16+1+len(frame.Endpoint)+16+32))
	buffer.WriteString("WAN1")
	buffer.Write(frame.ArmDigest[:])
	buffer.Write(frame.ProbeID[:])
	buffer.Write(frame.ProviderID[:])
	buffer.Write(frame.Activation[:])
	buffer.WriteByte(byte(len(frame.Endpoint)))
	buffer.WriteString(frame.Endpoint)
	buffer.Write(frame.ExpiryOpaque[:])
	buffer.Write(frame.Challenge[:])
	return buffer.Bytes()
}

func (frame ProviderFrame) MarshalBinary() []byte {
	return append(frame.signingBytes(), frame.Signature...)
}

// ParseProviderFrame is the bounded wire parser for the provider-hidden WAN frame.
// It rejects prefix collisions, truncated frames, malformed endpoints, and
// signatures with an unexpected length before authentication is attempted.
func ParseProviderFrame(payload []byte) (ProviderFrame, error) {
	var frame ProviderFrame
	const fixed = 4 + 32 + 16 + 16 + 16 + 1
	if len(payload) < fixed || len(payload) > providerFrameMax || !bytes.Equal(payload[:4], []byte("WAN1")) {
		return frame, ErrMalformedFrame
	}
	endpointLength := int(payload[fixed-1])
	const trailer = 16 + 32 + ed25519.SignatureSize
	expected := fixed + endpointLength + trailer
	if endpointLength == 0 || len(payload) != expected {
		return frame, ErrMalformedFrame
	}
	copy(frame.ArmDigest[:], payload[4:36])
	copy(frame.ProbeID[:], payload[36:52])
	copy(frame.ProviderID[:], payload[52:68])
	copy(frame.Activation[:], payload[68:84])
	frame.Endpoint = string(payload[fixed : fixed+endpointLength])
	if validateEndpoint(frame.Endpoint) != nil {
		return ProviderFrame{}, ErrMalformedFrame
	}
	trailerStart := fixed + endpointLength
	copy(frame.ExpiryOpaque[:], payload[trailerStart:trailerStart+16])
	copy(frame.Challenge[:], payload[trailerStart+16:trailerStart+48])
	frame.Signature = append([]byte(nil), payload[trailerStart+48:]...)
	return frame, nil
}

// ReadProviderFrame reads one bounded frame from a stream with a deadline, so
// partial and slow TCP ingress cannot allocate unbounded memory or block forever.
func ReadProviderFrame(connection net.Conn, maxFrame int, deadline time.Time) (ProviderFrame, error) {
	if connection == nil || maxFrame <= 0 || maxFrame > providerFrameMax {
		return ProviderFrame{}, ErrMalformedFrame
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return ProviderFrame{}, err
	}
	const fixed = 4 + 32 + 16 + 16 + 16 + 1
	header := make([]byte, fixed)
	if _, err := io.ReadFull(connection, header); err != nil {
		return ProviderFrame{}, err
	}
	if !bytes.Equal(header[:4], []byte("WAN1")) {
		return ProviderFrame{}, ErrMalformedFrame
	}
	endpointLength := int(header[fixed-1])
	const trailer = 16 + 32 + ed25519.SignatureSize
	total := fixed + endpointLength + trailer
	if endpointLength == 0 || total > maxFrame || total > providerFrameMax {
		return ProviderFrame{}, ErrMalformedFrame
	}
	rest := make([]byte, total-fixed)
	if _, err := io.ReadFull(connection, rest); err != nil {
		return ProviderFrame{}, err
	}
	return ParseProviderFrame(append(header, rest...))
}

type ProbeACK struct {
	ArmDigest     [32]byte
	ChallengeHash [32]byte
	Signature     []byte
}

func (ack ProbeACK) signingBytes() []byte {
	body := make([]byte, 4+32+32)
	copy(body[:4], "ACK1")
	copy(body[4:36], ack.ArmDigest[:])
	copy(body[36:], ack.ChallengeHash[:])
	return body
}

func (ack ProbeACK) MarshalBinary() []byte {
	return append(ack.signingBytes(), ack.Signature...)
}

type ProbeReceipt struct {
	ArmDigest     [32]byte
	ChallengeHash [32]byte
	ProviderID    [16]byte
	Signature     []byte
}

func (receipt ProbeReceipt) signingBytes() []byte {
	body := make([]byte, 4+32+32+16)
	copy(body[:4], "RCT1")
	copy(body[4:36], receipt.ArmDigest[:])
	copy(body[36:68], receipt.ChallengeHash[:])
	copy(body[68:], receipt.ProviderID[:])
	return body
}

type armedProbe struct {
	arm      ProbeArm
	digest   [32]byte
	deadline time.Time
	attempts int
}

type replayProbe struct {
	digest  [32]byte
	expires time.Time
}

type ProbeAgent struct {
	nodePrivate ed25519.PrivateKey
	mu          sync.Mutex
	operations  map[[16]byte]*armedProbe
	replay      map[[16]byte]replayProbe
	maxAttempts int
	maxOps      int
	maxReplay   int
}

func NewProbeAgent(nodePrivate ed25519.PrivateKey, maxAttempts int) *ProbeAgent {
	return NewProbeAgentWithLimits(nodePrivate, maxAttempts, defaultProbeOperations, defaultProbeReplay)
}

func NewProbeAgentWithLimits(nodePrivate ed25519.PrivateKey, maxAttempts, maxOperations, maxReplay int) *ProbeAgent {
	if maxOperations <= 0 {
		maxOperations = 1
	}
	if maxReplay <= 0 {
		maxReplay = 1
	}
	return &ProbeAgent{nodePrivate: append(ed25519.PrivateKey(nil), nodePrivate...), operations: make(map[[16]byte]*armedProbe), replay: make(map[[16]byte]replayProbe), maxAttempts: maxAttempts, maxOps: maxOperations, maxReplay: maxReplay}
}

func (agent *ProbeAgent) Arm(arm ProbeArm, now time.Time) (ProbeArmed, error) {
	if len(agent.nodePrivate) != ed25519.PrivateKeySize {
		return ProbeArmed{}, ErrInvalidEd25519Key
	}
	armBytes, err := arm.MarshalBinary()
	if err != nil {
		return ProbeArmed{}, err
	}
	digest := sha256.Sum256(armBytes)
	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.purgeLocked(now)
	if tombstone, exists := agent.replay[arm.ProbeID]; exists {
		if tombstone.digest == digest {
			return ProbeArmed{}, ErrProbeReplay
		}
		return ProbeArmed{}, ErrProbeIDConflict
	}
	if operation, exists := agent.operations[arm.ProbeID]; exists {
		if operation.digest != digest {
			return ProbeArmed{}, ErrProbeIDConflict
		}
		armed := ProbeArmed{ArmDigest: operation.digest}
		armed.Signature = ed25519.Sign(agent.nodePrivate, armedSigningBytes(armed.ArmDigest))
		return armed, nil
	}
	if len(agent.operations) >= agent.maxOps {
		return ProbeArmed{}, ErrProbeStateFull
	}
	agent.operations[arm.ProbeID] = &armedProbe{arm: cloneProbeArm(arm), digest: digest, deadline: now.Add(arm.TTL)}
	armed := ProbeArmed{ArmDigest: digest}
	armed.Signature = ed25519.Sign(agent.nodePrivate, armedSigningBytes(armed.ArmDigest))
	return armed, nil
}

func armedSigningBytes(digest [32]byte) []byte {
	body := make([]byte, 4+32)
	copy(body[:4], "RDY1")
	copy(body[4:], digest[:])
	return body
}

func VerifyArmed(nodePublic ed25519.PublicKey, arm ProbeArm, armed ProbeArmed) bool {
	if len(nodePublic) != ed25519.PublicKeySize {
		return false
	}
	armBytes, err := arm.MarshalBinary()
	if err != nil || sha256.Sum256(armBytes) != armed.ArmDigest {
		return false
	}
	return ed25519.Verify(nodePublic, armedSigningBytes(armed.ArmDigest), armed.Signature)
}

func SignProviderFrame(providerPrivate ed25519.PrivateKey, arm ProbeArm, challenge [32]byte) (ProviderFrame, error) {
	if len(providerPrivate) != ed25519.PrivateKeySize {
		return ProviderFrame{}, ErrInvalidEd25519Key
	}
	armBytes, err := arm.MarshalBinary()
	if err != nil {
		return ProviderFrame{}, err
	}
	frame := ProviderFrame{
		ArmDigest:    sha256.Sum256(armBytes),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(providerPrivate, frame.signingBytes())
	return frame, nil
}

func (agent *ProbeAgent) HandleIngress(sourceIP [4]byte, frame ProviderFrame, now time.Time) (ProbeOutcome, ProbeACK, ProbeReceipt) {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.purgeLocked(now)
	operation, ok := agent.operations[frame.ProbeID]
	if !ok || agent.maxAttempts <= 0 {
		return ProbeRejected, ProbeACK{}, ProbeReceipt{}
	}
	arm := operation.arm
	if now.After(operation.deadline) || sourceIP != arm.ExpectedSourceIP || frame.ArmDigest != operation.digest || frame.ProviderID != arm.ProviderID || frame.Activation != arm.Activation || frame.Endpoint != arm.Endpoint || frame.ExpiryOpaque != arm.ExpiryOpaque || validateEndpoint(frame.Endpoint) != nil || len(arm.ProviderPublicKey) != ed25519.PublicKeySize || len(frame.Signature) != ed25519.SignatureSize || !ed25519.Verify(arm.ProviderPublicKey, frame.signingBytes(), frame.Signature) {
		return ProbeRejected, ProbeACK{}, ProbeReceipt{}
	}
	if operation.attempts >= agent.maxAttempts {
		return ProbeRejected, ProbeACK{}, ProbeReceipt{}
	}
	operation.attempts++
	delete(agent.operations, frame.ProbeID)
	agent.addReplayLocked(frame.ProbeID, operation.digest, now.Add(probeReplayWindow))
	challengeHash := sha256.Sum256(frame.Challenge[:])
	ack := ProbeACK{ArmDigest: operation.digest, ChallengeHash: challengeHash}
	ack.Signature = ed25519.Sign(agent.nodePrivate, ack.signingBytes())
	receipt := ProbeReceipt{ArmDigest: operation.digest, ChallengeHash: challengeHash, ProviderID: arm.ProviderID}
	receipt.Signature = ed25519.Sign(agent.nodePrivate, receipt.signingBytes())
	return ProbeAccepted, ack, receipt
}

func (agent *ProbeAgent) purgeLocked(now time.Time) {
	for probeID, operation := range agent.operations {
		if !now.Before(operation.deadline) {
			delete(agent.operations, probeID)
			agent.addReplayLocked(probeID, operation.digest, operation.deadline.Add(probeReplayWindow))
		}
	}
	for probeID, tombstone := range agent.replay {
		if !now.Before(tombstone.expires) {
			delete(agent.replay, probeID)
		}
	}
}

func (agent *ProbeAgent) addReplayLocked(probeID [16]byte, digest [32]byte, expires time.Time) {
	if len(agent.replay) >= agent.maxReplay {
		var oldest [16]byte
		var oldestTime time.Time
		for id, tombstone := range agent.replay {
			if oldestTime.IsZero() || tombstone.expires.Before(oldestTime) {
				oldest, oldestTime = id, tombstone.expires
			}
		}
		if !oldestTime.IsZero() {
			delete(agent.replay, oldest)
		}
	}
	agent.replay[probeID] = replayProbe{digest: digest, expires: expires}
}

func VerifyProbeCompletion(nodePublic ed25519.PublicKey, arm ProbeArm, frame ProviderFrame, ack ProbeACK, receipt ProbeReceipt) bool {
	if len(nodePublic) != ed25519.PublicKeySize || len(arm.ProviderPublicKey) != ed25519.PublicKeySize || len(frame.Signature) != ed25519.SignatureSize || len(ack.Signature) != ed25519.SignatureSize || len(receipt.Signature) != ed25519.SignatureSize || validateEndpoint(frame.Endpoint) != nil {
		return false
	}
	armBytes, err := arm.MarshalBinary()
	if err != nil {
		return false
	}
	digest := sha256.Sum256(armBytes)
	challengeHash := sha256.Sum256(frame.Challenge[:])
	return frame.ArmDigest == digest && frame.ProbeID == arm.ProbeID && frame.ProviderID == arm.ProviderID && frame.Activation == arm.Activation && frame.Endpoint == arm.Endpoint && frame.ExpiryOpaque == arm.ExpiryOpaque && ed25519.Verify(arm.ProviderPublicKey, frame.signingBytes(), frame.Signature) && ack.ArmDigest == digest && ack.ChallengeHash == challengeHash && ed25519.Verify(nodePublic, ack.signingBytes(), ack.Signature) && receipt.ArmDigest == digest && receipt.ChallengeHash == challengeHash && receipt.ProviderID == arm.ProviderID && ed25519.Verify(nodePublic, receipt.signingBytes(), receipt.Signature)
}

func validateEndpoint(endpoint string) error {
	if endpoint == "" || len(endpoint) > 255 {
		return errors.New("endpoint must be bounded")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || net.ParseIP(host) == nil {
		return errors.New("endpoint must contain a concrete IP and port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return errors.New("endpoint port is invalid")
	}
	return nil
}

func cloneProbeArm(arm ProbeArm) ProbeArm {
	arm.ProviderPublicKey = append(ed25519.PublicKey(nil), arm.ProviderPublicKey...)
	return arm
}
