package contracts

// Frozen AntiNAT probe wire contract (docs/protocol.md §7).
//
// Two-phase arm + provider-hidden challenge, same-path Agent signature, and
// signed control receipt. The arm never contains the challenge; the provider
// introduces the challenge only at ingress. Invalid ingress exposes one
// generic REJECTED outcome with no authenticated material (anti-oracle).
//
// Frame magics (all fixed binary, never JSON):
//
//	ARM1  probe arm          signed by Controller
//	RDY1  probe armed        signed by Agent (node key)
//	WAN1  provider frame     signed by Provider (carries the challenge)
//	ACK1  same-path ACK      signed by Agent, returned on the ingress path
//	RCT1  control receipt    signed by Agent, sent over the control channel
//
// All lengths big-endian. Length-prefixed fields use a 1-byte length (fields
// are <= 255 bytes) unless stated otherwise.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

const (
	probeMagicArm      = "ARM1"
	probeMagicArmed    = "RDY1"
	probeMagicWAN      = "WAN1"
	probeMagicACK      = "ACK1"
	probeMagicReceipt  = "RCT1"
	probeIDLen         = 16
	probeProviderIDLen = 16
	probeActivationLen = 16
	probeNonceLen      = 32
	probeOpaqueLen     = 16
	probeDigestLen     = sha256.Size
	probeEndpointMax   = 255
	probeFrameMax      = 4 + 32 + 16 + 16 + 16 + 1 + probeEndpointMax + 16 + 32 + ed25519.SignatureSize
	probeReplayWindow  = 5 * time.Minute
	probeTTLMax        = 24 * time.Hour
)

var (
	ErrProbeMalformed  = errors.New("malformed probe frame")
	ErrProbeSignature  = errors.New("probe frame signature verification failed")
	ErrProbeReplay     = errors.New("probe ID is in the replay cache")
	ErrProbeIDConflict = errors.New("probe ID already armed with different material")
	ErrProbeStateFull  = errors.New("probe state capacity exhausted")
	ErrProbeChallenge  = errors.New("probe arm must never contain the provider challenge")
	ErrProbeEndpoint   = errors.New("probe endpoint is not a concrete IPv4:port")
)

// ---------------------------------------------------------------------------
// ProbeArm (ARM1, Controller -> Agent, signed by Controller)
// ---------------------------------------------------------------------------

type probeArm struct {
	probeID           [probeIDLen]byte
	providerID        [probeProviderIDLen]byte
	providerPublicKey ed25519.PublicKey
	expectedSourceIP  [4]byte
	activation        [probeActivationLen]byte
	endpoint          string
	ttlMS             uint64
	expiryOpaque      [probeOpaqueLen]byte
}

func (arm probeArm) canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString(probeMagicArm)
	buf.Write(arm.probeID[:])
	buf.Write(arm.providerID[:])
	buf.Write(arm.providerPublicKey)
	buf.Write(arm.expectedSourceIP[:])
	buf.Write(arm.activation[:])
	buf.WriteByte(byte(len(arm.endpoint)))
	buf.WriteString(arm.endpoint)
	var ttl [8]byte
	binary.BigEndian.PutUint64(ttl[:], arm.ttlMS)
	buf.Write(ttl[:])
	buf.Write(arm.expiryOpaque[:])
	return buf.Bytes()
}

func (arm probeArm) signingBytes() []byte {
	return arm.canonical() // domain is carried by the magic
}

func (arm probeArm) digest() [probeDigestLen]byte {
	return sha256.Sum256(arm.canonical())
}

// validProbeArm enforces the frozen arm invariants.
func validProbeArm(arm probeArm) error {
	if len(arm.providerPublicKey) != ed25519.PublicKeySize {
		return ErrProbeMalformed
	}
	if arm.ttlMS == 0 || arm.ttlMS > uint64(probeTTLMax/time.Millisecond) {
		return ErrProbeMalformed
	}
	if err := validProbeEndpoint(arm.endpoint); err != nil {
		return err
	}
	if len(arm.endpoint) == 0 || len(arm.endpoint) > probeEndpointMax {
		return ErrProbeMalformed
	}
	return nil
}

// parseProbeArm decodes and validates an ARM1 frame (signature not checked
// here; the enclosing control envelope carries the Controller signature).
func parseProbeArm(raw []byte) (probeArm, error) {
	var arm probeArm
	const fixed = 4 + probeIDLen + probeProviderIDLen + ed25519.PublicKeySize + 4 + probeActivationLen + 1
	if len(raw) < fixed || len(raw) > probeFrameMax || !bytes.Equal(raw[:4], []byte(probeMagicArm)) {
		return arm, ErrProbeMalformed
	}
	endpointLen := int(raw[fixed-1])
	expected := fixed + endpointLen + 8 + probeOpaqueLen
	if endpointLen == 0 || len(raw) != expected {
		return arm, ErrProbeMalformed
	}
	copy(arm.probeID[:], raw[4:4+probeIDLen])
	copy(arm.providerID[:], raw[4+probeIDLen:4+probeIDLen+probeProviderIDLen])
	arm.providerPublicKey = append(ed25519.PublicKey(nil), raw[4+probeIDLen+probeProviderIDLen:4+probeIDLen+probeProviderIDLen+ed25519.PublicKeySize]...)
	copy(arm.expectedSourceIP[:], raw[4+probeIDLen+probeProviderIDLen+ed25519.PublicKeySize:4+probeIDLen+probeProviderIDLen+ed25519.PublicKeySize+4])
	copy(arm.activation[:], raw[4+probeIDLen+probeProviderIDLen+ed25519.PublicKeySize+4:4+probeIDLen+probeProviderIDLen+ed25519.PublicKeySize+4+probeActivationLen])
	arm.endpoint = string(raw[fixed : fixed+endpointLen])
	arm.ttlMS = binary.BigEndian.Uint64(raw[fixed+endpointLen : fixed+endpointLen+8])
	copy(arm.expiryOpaque[:], raw[fixed+endpointLen+8:])
	if err := validProbeArm(arm); err != nil {
		return arm, err
	}
	return arm, nil
}

// ---------------------------------------------------------------------------
// ProbeArmed (RDY1, Agent -> Controller, signed by node key)
// ---------------------------------------------------------------------------

type probeArmed struct {
	armDigest [probeDigestLen]byte
	signature []byte
}

func (a probeArmed) signingBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(probeMagicArmed)
	buf.Write(a.armDigest[:])
	return buf.Bytes()
}

func parseProbeArmed(raw []byte, nodePub ed25519.PublicKey, wantDigest [probeDigestLen]byte) (probeArmed, error) {
	var a probeArmed
	const fixed = 4 + probeDigestLen
	if len(raw) != fixed+ed25519.SignatureSize || !bytes.Equal(raw[:4], []byte(probeMagicArmed)) {
		return a, ErrProbeMalformed
	}
	copy(a.armDigest[:], raw[4:fixed])
	a.signature = append([]byte(nil), raw[fixed:]...)
	if a.armDigest != wantDigest {
		return a, ErrProbeMalformed
	}
	if !ed25519.Verify(nodePub, a.signingBytes(), a.signature) {
		return a, ErrProbeSignature
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// ProviderFrame (WAN1, Provider -> Agent, signed by provider key)
// ---------------------------------------------------------------------------

type providerFrame struct {
	armDigest    [probeDigestLen]byte
	probeID      [probeIDLen]byte
	providerID   [probeProviderIDLen]byte
	activation   [probeActivationLen]byte
	endpoint     string
	expiryOpaque [probeOpaqueLen]byte
	challenge    [probeNonceLen]byte
	signature    []byte
}

func (f providerFrame) canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString(probeMagicWAN)
	buf.Write(f.armDigest[:])
	buf.Write(f.probeID[:])
	buf.Write(f.providerID[:])
	buf.Write(f.activation[:])
	buf.WriteByte(byte(len(f.endpoint)))
	buf.WriteString(f.endpoint)
	buf.Write(f.expiryOpaque[:])
	buf.Write(f.challenge[:])
	return buf.Bytes()
}

func (f providerFrame) signingBytes() []byte {
	return f.canonical()
}

func (f providerFrame) challengeHash() [probeDigestLen]byte {
	return sha256.Sum256(f.challenge[:])
}

// parseProviderFrame decodes and validates a WAN1 frame. The signature is
// NOT checked here; it is checked against the arm's provider key by the
// agent state machine.
func parseProviderFrame(raw []byte) (providerFrame, error) {
	var f providerFrame
	const fixed = 4 + probeDigestLen + probeIDLen + probeProviderIDLen + probeActivationLen + 1
	if len(raw) < fixed || len(raw) > probeFrameMax || !bytes.Equal(raw[:4], []byte(probeMagicWAN)) {
		return f, ErrProbeMalformed
	}
	endpointLen := int(raw[fixed-1])
	const trailer = probeOpaqueLen + probeNonceLen + ed25519.SignatureSize
	expected := fixed + endpointLen + trailer
	if endpointLen == 0 || len(raw) != expected {
		return f, ErrProbeMalformed
	}
	copy(f.armDigest[:], raw[4:4+probeDigestLen])
	copy(f.probeID[:], raw[4+probeDigestLen:4+probeDigestLen+probeIDLen])
	copy(f.providerID[:], raw[4+probeDigestLen+probeIDLen:4+probeDigestLen+probeIDLen+probeProviderIDLen])
	copy(f.activation[:], raw[4+probeDigestLen+probeIDLen+probeProviderIDLen:4+probeDigestLen+probeIDLen+probeProviderIDLen+probeActivationLen])
	f.endpoint = string(raw[fixed : fixed+endpointLen])
	if err := validProbeEndpoint(f.endpoint); err != nil {
		return f, err
	}
	trailerStart := fixed + endpointLen
	copy(f.expiryOpaque[:], raw[trailerStart:trailerStart+probeOpaqueLen])
	copy(f.challenge[:], raw[trailerStart+probeOpaqueLen:trailerStart+probeOpaqueLen+probeNonceLen])
	f.signature = append([]byte(nil), raw[trailerStart+probeOpaqueLen+probeNonceLen:]...)
	return f, nil
}

// ---------------------------------------------------------------------------
// ProbeACK (ACK1, Agent -> Provider, same-path, signed by node key)
// ---------------------------------------------------------------------------

type probeACK struct {
	armDigest     [probeDigestLen]byte
	challengeHash [probeDigestLen]byte
	signature     []byte
}

func (a probeACK) signingBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(probeMagicACK)
	buf.Write(a.armDigest[:])
	buf.Write(a.challengeHash[:])
	return buf.Bytes()
}

func parseProbeACK(raw []byte, nodePub ed25519.PublicKey) (probeACK, error) {
	var a probeACK
	const fixed = 4 + probeDigestLen + probeDigestLen
	if len(raw) != fixed+ed25519.SignatureSize || !bytes.Equal(raw[:4], []byte(probeMagicACK)) {
		return a, ErrProbeMalformed
	}
	copy(a.armDigest[:], raw[4:4+probeDigestLen])
	copy(a.challengeHash[:], raw[4+probeDigestLen:fixed])
	a.signature = append([]byte(nil), raw[fixed:]...)
	if !ed25519.Verify(nodePub, a.signingBytes(), a.signature) {
		return a, ErrProbeSignature
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// ProbeReceipt (RCT1, Agent -> Controller control channel, signed by node key)
// ---------------------------------------------------------------------------

type probeReceipt struct {
	armDigest     [probeDigestLen]byte
	challengeHash [probeDigestLen]byte
	providerID    [probeProviderIDLen]byte
	signature     []byte
}

func (r probeReceipt) signingBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(probeMagicReceipt)
	buf.Write(r.armDigest[:])
	buf.Write(r.challengeHash[:])
	buf.Write(r.providerID[:])
	return buf.Bytes()
}

func parseProbeReceipt(raw []byte, nodePub ed25519.PublicKey) (probeReceipt, error) {
	var r probeReceipt
	const fixed = 4 + probeDigestLen + probeDigestLen + probeProviderIDLen
	if len(raw) != fixed+ed25519.SignatureSize || !bytes.Equal(raw[:4], []byte(probeMagicReceipt)) {
		return r, ErrProbeMalformed
	}
	copy(r.armDigest[:], raw[4:4+probeDigestLen])
	copy(r.challengeHash[:], raw[4+probeDigestLen:4+2*probeDigestLen])
	copy(r.providerID[:], raw[4+2*probeDigestLen:fixed])
	r.signature = append([]byte(nil), raw[fixed:]...)
	if !ed25519.Verify(nodePub, r.signingBytes(), r.signature) {
		return r, ErrProbeSignature
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// ProbeAgent state machine: arm -> provider ingress -> same-path ACK +
// control receipt, consumed exactly once, replay-cached, anti-oracle.
// ---------------------------------------------------------------------------

type armedProbeState struct {
	arm      probeArm
	digest   [probeDigestLen]byte
	deadline time.Time
	used     bool
}

type probeAgentState struct {
	nodeKey ed25519.PrivateKey
	ops     map[[probeIDLen]byte]*armedProbeState
	replay  map[[probeIDLen]byte]time.Time
}

func newProbeAgentState(nodeKey ed25519.PrivateKey) *probeAgentState {
	return &probeAgentState{
		nodeKey: nodeKey,
		ops:     map[[probeIDLen]byte]*armedProbeState{},
		replay:  map[[probeIDLen]byte]time.Time{},
	}
}

// armProbe persists a validated arm and returns the signed armed response.
// The arm must not contain the challenge; if it does, arming fails closed.
func (s *probeAgentState) armProbe(arm probeArm, now time.Time) (probeArmed, error) {
	if err := validProbeArm(arm); err != nil {
		return probeArmed{}, err
	}
	digest := arm.digest()
	// Replay/conflict resolution before any state is written.
	if expire, ok := s.replay[arm.probeID]; ok {
		if now.Before(expire) {
			if old, ok := s.ops[arm.probeID]; ok && old.digest == digest {
				return probeArmed{}, ErrProbeReplay
			}
			return probeArmed{}, ErrProbeIDConflict
		}
		delete(s.replay, arm.probeID)
	}
	if old, ok := s.ops[arm.probeID]; ok {
		if old.digest != digest {
			return probeArmed{}, ErrProbeIDConflict
		}
		return probeArmed{armDigest: digest, signature: ed25519.Sign(s.nodeKey, (&probeArmed{armDigest: digest}).signingBytes())}, nil
	}
	s.ops[arm.probeID] = &armedProbeState{arm: arm, digest: digest, deadline: now.Add(time.Duration(arm.ttlMS) * time.Millisecond)}
	armed := probeArmed{armDigest: digest, signature: ed25519.Sign(s.nodeKey, (&probeArmed{armDigest: digest}).signingBytes())}
	return armed, nil
}

// handleProbeIngress consumes a provider frame against the armed operation.
// Every failure mode returns the same generic REJECTED with zero authenticated
// material (anti-oracle). Success returns the same-path ACK plus the signed
// control receipt and consumes the operation exactly once.
func (s *probeAgentState) handleProbeIngress(frame providerFrame, sourceIP [4]byte, now time.Time) (accepted bool) {
	op, ok := s.ops[frame.probeID]
	if !ok || op.used || now.After(op.deadline) {
		return false
	}
	arm := op.arm
	if sourceIP != arm.expectedSourceIP ||
		frame.armDigest != op.digest ||
		frame.providerID != arm.providerID ||
		frame.activation != arm.activation ||
		frame.endpoint != arm.endpoint ||
		frame.expiryOpaque != arm.expiryOpaque ||
		!ed25519.Verify(arm.providerPublicKey, frame.signingBytes(), frame.signature) {
		return false
	}
	op.used = true
	s.replay[frame.probeID] = now.Add(probeReplayWindow)
	return true
}

// verifyProbeJoin is the Controller-side join: provider result + Agent
// same-path ACK + Agent control receipt must all bind to the same operation.
func verifyProbeJoin(arm probeArm, frame providerFrame, ack probeACK, receipt probeReceipt, nodePub ed25519.PublicKey) bool {
	if err := validProbeArm(arm); err != nil {
		return false
	}
	digest := arm.digest()
	if frame.armDigest != digest || ack.armDigest != digest || receipt.armDigest != digest {
		return false
	}
	if frame.probeID != arm.probeID || frame.providerID != arm.providerID || frame.activation != arm.activation ||
		frame.endpoint != arm.endpoint || frame.expiryOpaque != arm.expiryOpaque {
		return false
	}
	if receipt.providerID != arm.providerID {
		return false
	}
	if !ed25519.Verify(arm.providerPublicKey, frame.signingBytes(), frame.signature) {
		return false
	}
	ch := frame.challengeHash()
	if ack.challengeHash != ch || receipt.challengeHash != ch {
		return false
	}
	if !ed25519.Verify(nodePub, ack.signingBytes(), ack.signature) || !ed25519.Verify(nodePub, receipt.signingBytes(), receipt.signature) {
		return false
	}
	return true
}

func validProbeEndpoint(endpoint string) error {
	if endpoint == "" || len(endpoint) > probeEndpointMax {
		return ErrProbeEndpoint
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return ErrProbeEndpoint
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return ErrProbeEndpoint
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return ErrProbeEndpoint
	}
	return nil
}

func probeDigestOf(arm probeArm) [probeDigestLen]byte { return arm.digest() }
