package network

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
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
		return nil, errors.New("provider public key must be Ed25519")
	}
	if arm.TTL <= 0 || arm.Endpoint == "" || len(arm.Endpoint) > 255 {
		return nil, errors.New("arm requires positive TTL and bounded endpoint")
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 4+16+16+32+4+16+1+len(arm.Endpoint)+8+16))
	buffer.WriteString("ARM1")
	buffer.Write(arm.ProbeID[:])
	buffer.Write(arm.ProviderID[:])
	buffer.Write(arm.ProviderPublicKey)
	buffer.Write(arm.ExpectedSourceIP[:])
	buffer.Write(arm.Activation[:])
	buffer.WriteByte(byte(len(arm.Endpoint)))
	buffer.WriteString(arm.Endpoint)
	binary.Write(buffer, binary.BigEndian, uint64(arm.TTL))
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
	consumed bool
}

type ProbeAgent struct {
	nodePrivate ed25519.PrivateKey
	operations  map[[16]byte]*armedProbe
	maxAttempts int
}

func NewProbeAgent(nodePrivate ed25519.PrivateKey, maxAttempts int) *ProbeAgent {
	return &ProbeAgent{nodePrivate: append(ed25519.PrivateKey(nil), nodePrivate...), operations: make(map[[16]byte]*armedProbe), maxAttempts: maxAttempts}
}

func (agent *ProbeAgent) Arm(arm ProbeArm, now time.Time) (ProbeArmed, error) {
	armBytes, err := arm.MarshalBinary()
	if err != nil {
		return ProbeArmed{}, err
	}
	digest := sha256.Sum256(armBytes)
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
	armBytes, err := arm.MarshalBinary()
	if err != nil || sha256.Sum256(armBytes) != armed.ArmDigest {
		return false
	}
	return ed25519.Verify(nodePublic, armedSigningBytes(armed.ArmDigest), armed.Signature)
}

func SignProviderFrame(providerPrivate ed25519.PrivateKey, arm ProbeArm, challenge [32]byte) (ProviderFrame, error) {
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
	operation, ok := agent.operations[frame.ProbeID]
	if !ok || operation.consumed || operation.attempts >= agent.maxAttempts {
		return ProbeRejected, ProbeACK{}, ProbeReceipt{}
	}
	operation.attempts++
	arm := operation.arm
	if now.After(operation.deadline) || sourceIP != arm.ExpectedSourceIP || frame.ArmDigest != operation.digest || frame.ProviderID != arm.ProviderID || frame.Activation != arm.Activation || frame.Endpoint != arm.Endpoint || frame.ExpiryOpaque != arm.ExpiryOpaque || !ed25519.Verify(arm.ProviderPublicKey, frame.signingBytes(), frame.Signature) {
		return ProbeRejected, ProbeACK{}, ProbeReceipt{}
	}
	operation.consumed = true
	challengeHash := sha256.Sum256(frame.Challenge[:])
	ack := ProbeACK{ArmDigest: operation.digest, ChallengeHash: challengeHash}
	ack.Signature = ed25519.Sign(agent.nodePrivate, ack.signingBytes())
	receipt := ProbeReceipt{ArmDigest: operation.digest, ChallengeHash: challengeHash, ProviderID: arm.ProviderID}
	receipt.Signature = ed25519.Sign(agent.nodePrivate, receipt.signingBytes())
	return ProbeAccepted, ack, receipt
}

func VerifyProbeCompletion(nodePublic ed25519.PublicKey, arm ProbeArm, frame ProviderFrame, ack ProbeACK, receipt ProbeReceipt) bool {
	armBytes, err := arm.MarshalBinary()
	if err != nil {
		return false
	}
	digest := sha256.Sum256(armBytes)
	challengeHash := sha256.Sum256(frame.Challenge[:])
	return frame.ArmDigest == digest && frame.ProbeID == arm.ProbeID && frame.ProviderID == arm.ProviderID && frame.Activation == arm.Activation && frame.Endpoint == arm.Endpoint && frame.ExpiryOpaque == arm.ExpiryOpaque && ed25519.Verify(arm.ProviderPublicKey, frame.signingBytes(), frame.Signature) && ack.ArmDigest == digest && ack.ChallengeHash == challengeHash && ed25519.Verify(nodePublic, ack.signingBytes(), ack.Signature) && receipt.ArmDigest == digest && receipt.ChallengeHash == challengeHash && receipt.ProviderID == arm.ProviderID && ed25519.Verify(nodePublic, receipt.signingBytes(), receipt.Signature)
}

func cloneProbeArm(arm ProbeArm) ProbeArm {
	arm.ProviderPublicKey = append(ed25519.PublicKey(nil), arm.ProviderPublicKey...)
	return arm
}
