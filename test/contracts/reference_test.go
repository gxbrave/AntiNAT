package contracts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// ---------------------------------------------------------------------------
// Frozen AntiNAT control-envelope wire format (docs/protocol.md).
//
// Frame layout (all lengths big-endian):
//
//	[0:4]    magic              "ANAT"
//	[4:5]    wire_version       uint8 = 1
//	[5:9]    header_len         uint32
//	[9:13]   payload_len        uint32
//	[13:13+h] protected_header_bytes
//	[13+h:13+h+p] raw_payload_bytes
//	[...]    signature          Ed25519, 64 bytes
//
// Protected header: length-prefixed fields in fixed order
// (uint32 BE length + raw bytes), exactly 14 fields:
//
//	1  protocol_domain          (utf8, "AntiNAT-Control-v1")
//	2  controller_instance_id   (16 bytes)
//	3  node_id                  (16 bytes)
//	4  controller_key_id        (utf8)
//	5  agent_credential_version (uint32 BE)
//	6  connection_epoch         (uint64 BE)
//	7  session_id               (utf8)
//	8  direction                (1 byte: 0x01 C2A, 0x02 A2C)
//	9  sequence                 (uint64 BE)
//	10 message_id               (16 bytes)
//	11 message_type             (utf8)
//	12 schema_version           (uint32 BE)
//	13 payload_length           (uint64 BE)
//	14 payload_sha256           (32 bytes)
//
// Signature input = protocol_domain_bytes || protected_header_bytes ||
// payload_sha256_bytes. Ed25519, verified against the pinned peer key.
// ---------------------------------------------------------------------------

const (
	protocolDomain            = "AntiNAT-Control-v1"
	envelopeMagic             = "ANAT"
	wireVersion               = 1
	maxHeaderBytes            = 4096
	maxPayloadBytes           = 65536
	maxJSONDepth              = 16
	envelopeSigLen            = ed25519.SignatureSize
	dirControllerToAgent byte = 0x01
	dirAgentToController byte = 0x02

	controllerKeyID = "controller-key-1"
	agentKeyID      = "agent-key-1"
	providerKeyID   = "provider-key-1"
)

// rejectStage is the phase at which a parser rejected a frame. The frozen
// contract requires all wire/header/hash/signature failures to happen BEFORE
// any payload decode; only strict JSON payload validation may fail in the
// payload stage.
type rejectStage int

const (
	stageOK rejectStage = iota
	stageFraming
	stageHeader
	stageConsistency
	stageSignature
	stagePayloadJSON
)

func (s rejectStage) String() string {
	switch s {
	case stageFraming:
		return "framing"
	case stageHeader:
		return "header"
	case stageConsistency:
		return "consistency"
	case stageSignature:
		return "signature"
	case stagePayloadJSON:
		return "payload_json"
	default:
		return "ok"
	}
}

// envelope is a fully parsed control envelope.
type envelope struct {
	headerLen   uint32
	payloadLen  uint32
	headerBytes []byte
	payload     []byte
	signature   []byte
	header      protectedHeader
}

type protectedHeader struct {
	protocolDomain       string
	controllerInstanceID [16]byte
	nodeID               [16]byte
	controllerKeyID      string
	agentCredentialVer   uint32
	connectionEpoch      uint64
	sessionID            string
	direction            byte
	sequence             uint64
	messageID            [16]byte
	messageType          string
	schemaVersion        uint32
	payloadLength        uint64
	payloadSHA256        [32]byte
}

// encodeProtectedHeader renders the canonical length-prefixed header.
func encodeProtectedHeader(h protectedHeader) ([]byte, error) {
	var buf bytes.Buffer
	putField := func(b []byte) error {
		if len(b) > math.MaxUint32 {
			return errors.New("header field too large")
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
		return nil
	}
	fields := [][]byte{
		[]byte(h.protocolDomain),
		h.controllerInstanceID[:],
		h.nodeID[:],
		[]byte(h.controllerKeyID),
		encodeU32(h.agentCredentialVer),
		encodeU64(h.connectionEpoch),
		[]byte(h.sessionID),
		{h.direction},
		encodeU64(h.sequence),
		h.messageID[:],
		[]byte(h.messageType),
		encodeU32(h.schemaVersion),
		encodeU64(h.payloadLength),
		h.payloadSHA256[:],
	}
	for _, f := range fields {
		if err := putField(f); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func encodeU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func encodeU64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// decodeProtectedHeader parses and validates the 14 canonical fields.
func decodeProtectedHeader(b []byte) (protectedHeader, error) {
	var h protectedHeader
	idx := 0
	next := func() ([]byte, error) {
		if len(b)-idx < 4 {
			return nil, errors.New("header truncated in length prefix")
		}
		l := binary.BigEndian.Uint32(b[idx : idx+4])
		idx += 4
		if uint64(l) > uint64(len(b)-idx) {
			return nil, errors.New("header field length exceeds header")
		}
		f := b[idx : idx+int(l)]
		idx += int(l)
		return f, nil
	}
	var err error
	fieldCount := 0
	read := func(target *[]byte) error {
		ff, e := next()
		if e != nil {
			return e
		}
		*target = ff
		fieldCount++
		return nil
	}
	var parts [14][]byte
	for i := range parts {
		if err = read(&parts[i]); err != nil {
			return h, err
		}
	}
	if idx != len(b) {
		return h, errors.New("trailing bytes after protected header")
	}
	if fieldCount != 14 {
		return h, fmt.Errorf("protected header field count %d != 14", fieldCount)
	}
	h.protocolDomain = string(parts[0])
	if len(parts[1]) != 16 {
		return h, errors.New("controller_instance_id must be 16 bytes")
	}
	copy(h.controllerInstanceID[:], parts[1])
	if len(parts[2]) != 16 {
		return h, errors.New("node_id must be 16 bytes")
	}
	copy(h.nodeID[:], parts[2])
	h.controllerKeyID = string(parts[3])
	if len(parts[4]) != 4 {
		return h, errors.New("agent_credential_version must be 4 bytes")
	}
	h.agentCredentialVer = binary.BigEndian.Uint32(parts[4])
	if len(parts[5]) != 8 {
		return h, errors.New("connection_epoch must be 8 bytes")
	}
	h.connectionEpoch = binary.BigEndian.Uint64(parts[5])
	h.sessionID = string(parts[6])
	if len(parts[7]) != 1 {
		return h, errors.New("direction must be 1 byte")
	}
	h.direction = parts[7][0]
	if len(parts[8]) != 8 {
		return h, errors.New("sequence must be 8 bytes")
	}
	h.sequence = binary.BigEndian.Uint64(parts[8])
	if len(parts[9]) != 16 {
		return h, errors.New("message_id must be 16 bytes")
	}
	copy(h.messageID[:], parts[9])
	h.messageType = string(parts[10])
	if len(parts[11]) != 4 {
		return h, errors.New("schema_version must be 4 bytes")
	}
	h.schemaVersion = binary.BigEndian.Uint32(parts[11])
	if len(parts[12]) != 8 {
		return h, errors.New("payload_length must be 8 bytes")
	}
	h.payloadLength = binary.BigEndian.Uint64(parts[12])
	if len(parts[13]) != 32 {
		return h, errors.New("payload_sha256 must be 32 bytes")
	}
	copy(h.payloadSHA256[:], parts[13])
	return h, nil
}

// buildEnvelope assembles a frame and signs it.
func buildEnvelope(priv ed25519.PrivateKey, h protectedHeader, payload []byte) ([]byte, error) {
	h.payloadLength = uint64(len(payload))
	sum := sha256.Sum256(payload)
	h.payloadSHA256 = sum
	headerBytes, err := encodeProtectedHeader(h)
	if err != nil {
		return nil, err
	}
	if len(headerBytes) > maxHeaderBytes {
		return nil, errors.New("protected header exceeds maxHeaderBytes")
	}
	if len(payload) > maxPayloadBytes {
		return nil, errors.New("payload exceeds maxPayloadBytes")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	sigInput := append(append([]byte(h.protocolDomain), headerBytes...), h.payloadSHA256[:]...)
	sig := ed25519.Sign(priv, sigInput)

	frame := make([]byte, 0, 13+len(headerBytes)+len(payload)+envelopeSigLen)
	frame = append(frame, envelopeMagic...)
	frame = append(frame, wireVersion)
	frame = append(frame, encodeU32(uint32(len(headerBytes)))...)
	frame = append(frame, encodeU32(uint32(len(payload)))...)
	frame = append(frame, headerBytes...)
	frame = append(frame, payload...)
	frame = append(frame, sig...)
	return frame, nil
}

// parseEnvelope validates framing, header, consistency, and signature in
// order and returns the stage at which validation stopped. It never decodes
// the payload; payload validation is a separate stage.
func parseEnvelope(frame []byte, peer ed25519.PublicKey) (envelope, rejectStage, error) {
	var env envelope
	if len(frame) < 13+envelopeSigLen {
		return env, stageFraming, errors.New("frame shorter than minimum envelope")
	}
	if !bytes.Equal(frame[:4], []byte(envelopeMagic)) {
		return env, stageFraming, errors.New("bad magic")
	}
	if frame[4] != wireVersion {
		return env, stageFraming, errors.New("unsupported wire version")
	}
	headerLen := binary.BigEndian.Uint32(frame[5:9])
	payloadLen := binary.BigEndian.Uint32(frame[9:13])
	if headerLen == 0 || headerLen > maxHeaderBytes {
		return env, stageFraming, errors.New("header length out of range")
	}
	if payloadLen > maxPayloadBytes {
		return env, stageFraming, errors.New("payload length out of range")
	}
	if uint64(len(frame)) != uint64(13)+uint64(headerLen)+uint64(payloadLen)+uint64(envelopeSigLen) {
		return env, stageFraming, errors.New("frame length inconsistent with declared lengths")
	}
	headerBytes := frame[13 : 13+headerLen]
	payload := frame[13+headerLen : 13+headerLen+payloadLen]
	sig := frame[13+headerLen+payloadLen:]

	header, err := decodeProtectedHeader(headerBytes)
	if err != nil {
		return env, stageHeader, err
	}
	if header.protocolDomain != protocolDomain {
		return env, stageConsistency, errors.New("protocol domain mismatch")
	}
	if header.payloadLength != uint64(payloadLen) {
		return env, stageConsistency, errors.New("payload_length header field does not match frame length")
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:], header.payloadSHA256[:]) {
		return env, stageConsistency, errors.New("payload sha256 mismatch")
	}
	if header.direction != dirControllerToAgent && header.direction != dirAgentToController {
		return env, stageConsistency, errors.New("invalid direction byte")
	}
	if header.agentCredentialVer == 0 {
		return env, stageConsistency, errors.New("agent credential version must be non-zero")
	}
	if len(peer) != ed25519.PublicKeySize {
		return env, stageConsistency, errors.New("invalid peer key size")
	}
	sigInput := append(append([]byte(header.protocolDomain), headerBytes...), header.payloadSHA256[:]...)
	if !ed25519.Verify(peer, sigInput, sig) {
		return env, stageSignature, errors.New("signature verification failed")
	}
	env.headerLen = headerLen
	env.payloadLen = payloadLen
	env.headerBytes = headerBytes
	env.payload = payload
	env.signature = sig
	env.header = header
	return env, stageOK, nil
}

// ---------------------------------------------------------------------------
// Strict JSON payload validation (docs/protocol.md). Payloads are single JSON
// objects; duplicate keys, unknown fields, nesting > 16, out-of-range
// numbers, and trailing garbage are rejected.
// ---------------------------------------------------------------------------

type strictJSON struct {
	dec *json.Decoder
}

// validateStrictJSON parses payload as a strict JSON object with the allowed
// field set. Duplicate keys are rejected by decoding into an ordered token
// stream; unknown top-level and nested fields are rejected against the
// message schema; nesting depth is bounded; numbers must be finite and within
// the Go int64 range for integer fields.
func validateStrictJSON(payload []byte, schema map[string]fieldKind) error {
	if len(payload) == 0 {
		return errors.New("payload is empty")
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	d.Token() // consume '{'
	if err := walkObject(d, schema, 0); err != nil {
		return err
	}
	// Ensure no trailing garbage.
	if _, err := d.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing content after JSON object")
		}
		return err
	}
	return nil
}

type fieldKind int

const (
	kindString fieldKind = iota
	kindInt
	kindBool
	kindHex
	kindStringArray
	kindObject
	kindAny
)

func walkObject(d *json.Decoder, schema map[string]fieldKind, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("json nesting exceeds %d", maxJSONDepth)
	}
	seen := map[string]bool{}
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				return errors.New("unterminated JSON object")
			}
			return err
		}
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("JSON object key is not a string")
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q", key)
		}
		seen[key] = true
		kind, allowed := schema[key]
		if !allowed {
			if schema == nil {
				// No schema provided: this is a shape-only validation pass
				// (e.g. nested object or a syntax-only check), so any field
				// name is permitted with unconstrained value kind.
				kind = kindAny
			} else {
				return fmt.Errorf("unknown JSON field %q", key)
			}
		}
		if err := walkValue(d, kind, depth+1); err != nil {
			return err
		}
	}
}

func walkValue(d *json.Decoder, kind fieldKind, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("json nesting exceeds %d", maxJSONDepth)
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return walkObject(d, nil, depth)
		case '[':
			for {
				t, e := d.Token()
				if e != nil {
					if e == io.EOF {
						return errors.New("unterminated JSON array")
					}
					return e
				}
				if delim, ok := t.(json.Delim); ok && delim == ']' {
					return nil
				}
				if err := checkScalar(t, kindAny); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	case string:
		if kind == kindInt {
			return errors.New("expected integer, got string")
		}
		if kind == kindHex {
			if _, err := hex.DecodeString(v); err != nil {
				return fmt.Errorf("field is not hex: %w", err)
			}
		}
		if kind == kindStringArray {
			return errors.New("expected array of strings, got string")
		}
		return nil
	case json.Number:
		if kind == kindString {
			return errors.New("expected string, got number")
		}
		if !isBoundedJSONNumber(v) {
			return fmt.Errorf("out-of-range number %s", v.String())
		}
		return nil
	case bool:
		if kind == kindString || kind == kindInt {
			return errors.New("unexpected boolean for field kind")
		}
		return nil
	case nil:
		return nil
	default:
		return errors.New("unexpected JSON token")
	}
}

func checkScalar(t json.Token, kind fieldKind) error {
	switch v := t.(type) {
	case json.Number:
		if !isBoundedJSONNumber(v) {
			return fmt.Errorf("out-of-range number %s", v.String())
		}
	case string, bool, nil:
		return nil
	default:
		return errors.New("unexpected JSON token in array")
	}
	return nil
}

// isBoundedJSONNumber returns true for finite JSON numbers within the int64
// range, excluding int64 min (-9223372036854775808).
func isBoundedJSONNumber(n json.Number) bool {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return false
	}
	// Must be within int64 range.
	if strings.HasPrefix(s, "-") {
		s = s[1:]
	}
	if len(s) == 0 {
		return false
	}
	// Compare digit strings against 9223372036854775807.
	const maxI64 = "9223372036854775807"
	if len(s) < len(maxI64) {
		return true
	}
	if len(s) > len(maxI64) {
		return false
	}
	return s <= maxI64
}

// strictJSONDecode is the single-entry strict decoder used by validators.
func strictJSONDecode(payload []byte, schema map[string]fieldKind) (map[string]any, error) {
	if len(payload) == 0 {
		return nil, errors.New("payload is empty")
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	out := map[string]any{}
	if err := decodeStrictObject(d, schema, 0, out); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing content after JSON object")
		}
		return nil, err
	}
	return out, nil
}

func decodeStrictObject(d *json.Decoder, schema map[string]fieldKind, depth int, out map[string]any) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("json nesting exceeds %d", maxJSONDepth)
	}
	seen := map[string]bool{}
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				return errors.New("unterminated JSON object")
			}
			return err
		}
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("JSON object key is not a string")
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q", key)
		}
		seen[key] = true
		kind, allowed := schema[key]
		if !allowed {
			if schema == nil {
				kind = kindAny
			} else {
				return fmt.Errorf("unknown JSON field %q", key)
			}
		}
		val, err := decodeStrictValue(d, kind, depth+1)
		if err != nil {
			return err
		}
		out[key] = val
	}
}

func decodeStrictValue(d *json.Decoder, kind fieldKind, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("json nesting exceeds %d", maxJSONDepth)
	}
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			obj := map[string]any{}
			if err := decodeStrictObject(d, nil, depth, obj); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for {
				t, e := d.Token()
				if e != nil {
					if e == io.EOF {
						return nil, errors.New("unterminated JSON array")
					}
					return nil, e
				}
				if delim, ok := t.(json.Delim); ok && delim == ']' {
					return arr, nil
				}
				sv, e := decodeScalarToken(t, kindAny)
				if e != nil {
					return nil, e
				}
				arr = append(arr, sv)
			}
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	default:
		return decodeScalarToken(tok, kind)
	}
}

func decodeScalarToken(tok json.Token, kind fieldKind) (any, error) {
	switch v := tok.(type) {
	case string:
		if kind == kindStringArray {
			return nil, errors.New("expected array, got string")
		}
		return v, nil
	case json.Number:
		if !isBoundedJSONNumber(v) {
			return nil, fmt.Errorf("out-of-range number %s", v.String())
		}
		return v.Int64()
	case bool:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, errors.New("unexpected JSON token")
	}
}

// pinnedKeys are deterministic TEST-ONLY keys used to sign the frozen golden
// vectors. They are published fixture keys, never real credentials.
func controllerPriv() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
}

func agentPriv() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
}

func providerPriv() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32))
}

func controllerPub() ed25519.PublicKey { return controllerPriv().Public().(ed25519.PublicKey) }
func agentPub() ed25519.PublicKey      { return agentPriv().Public().(ed25519.PublicKey) }
func providerPub() ed25519.PublicKey   { return providerPriv().Public().(ed25519.PublicKey) }

// hexEncode and hexDecode helpers for fixture IO.
func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(t string) ([]byte, error) { return hex.DecodeString(t) }
