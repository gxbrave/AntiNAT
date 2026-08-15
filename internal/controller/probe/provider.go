// Controller <-> provider protocol (operator-owned, P10-defined). The
// provider is the operator-pinned antinat-probe service; the contract only
// freezes the agent-facing frames (ARM1/RDY1/WAN1/ACK1/RCT1). The request is
// signed by the controller key; the result is signed by the provider key.
package probe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

const (
	providerRequestSchema = "antinat.provider-request/v1"
	providerResultSchema  = "antinat.provider-result/v1"
)

// providerRequest is the signed controller -> provider request. It binds the
// node public key (so the provider can verify the agent-signed ACK1), the
// probe id, activation, exact endpoint, and the provider policy fields from
// the arm. It never carries the challenge.
type providerRequest struct {
	Schema             string `json:"schema"`
	ControllerInstance string `json:"controller_instance_id"`
	ControllerKeyID    string `json:"controller_key_id"`
	NodePublicKey      string `json:"node_public_key"`
	NodePublicKeyHash  string `json:"node_public_key_hash"`
	ProbeID            string `json:"probe_id"`
	ProviderID         string `json:"provider_id"`
	Activation         string `json:"activation"`
	Endpoint           string `json:"endpoint"`
	ExpectedSourceIP   string `json:"expected_source_ip"`
	ExpiryOpaque       string `json:"expiry_opaque"`
	TTLMS              uint64 `json:"ttl_ms"`
	ArmDigest          string `json:"arm_digest"`
	TimestampUnix      int64  `json:"timestamp_unix"`
	Signature          string `json:"signature"`
}

// canonical renders the exact signed bytes (all fields except signature).
func (r *providerRequest) canonical() ([]byte, error) {
	// Explicit field list so adding a field never silently changes what is
	// signed; hex-encoded fields are lowercased for canonical form.
	fields := []string{
		r.Schema, r.ControllerInstance, r.ControllerKeyID,
		strings.ToLower(r.NodePublicKey), strings.ToLower(r.NodePublicKeyHash),
		strings.ToLower(r.ProbeID), strings.ToLower(r.ProviderID),
		strings.ToLower(r.Activation), r.Endpoint,
		strings.ToLower(r.ExpectedSourceIP), strings.ToLower(r.ExpiryOpaque),
		fmt.Sprintf("%d", r.TTLMS), strings.ToLower(r.ArmDigest),
		fmt.Sprintf("%d", r.TimestampUnix),
	}
	return []byte(strings.Join(fields, "\x00")), nil
}

// decodeProviderRequest verifies the controller signature against the pinned
// controller public key and decodes the request.
func decodeProviderRequest(body io.Reader, controllerPub ed25519.PublicKey) (*providerRequest, error) {
	return decodeProviderRequestAt(body, controllerPub, time.Now())
}

func decodeProviderRequestAt(body io.Reader, controllerPub ed25519.PublicKey, nowTime time.Time) (*providerRequest, error) {
	var req providerRequest
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("provider: trailing JSON")
		}
		return nil, err
	}
	if req.Schema != providerRequestSchema {
		return nil, errors.New("provider: wrong request schema")
	}
	if req.Signature == "" || req.Endpoint == "" || req.ControllerInstance == "" || req.ControllerKeyID == "" {
		return nil, errors.New("provider: incomplete request")
	}
	for label, value := range map[string]string{
		"node_public_key": req.NodePublicKey, "node_public_key_hash": req.NodePublicKeyHash,
		"probe_id": req.ProbeID, "provider_id": req.ProviderID, "activation": req.Activation,
		"expected_source_ip": req.ExpectedSourceIP, "expiry_opaque": req.ExpiryOpaque,
		"arm_digest": req.ArmDigest,
	} {
		if value == "" {
			return nil, fmt.Errorf("provider: missing %s", label)
		}
	}
	for label, size := range map[string]int{
		"node_public_key": ed25519.PublicKeySize, "node_public_key_hash": 32,
		"probe_id": protocol.ProbeIDLen, "provider_id": protocol.ProbeProviderIDLen,
		"activation": protocol.ProbeActivationLen, "expected_source_ip": 4,
		"expiry_opaque": protocol.ProbeOpaqueLen, "arm_digest": protocol.ProbeDigestLen,
	} {
		value := map[string]string{
			"node_public_key": req.NodePublicKey, "node_public_key_hash": req.NodePublicKeyHash,
			"probe_id": req.ProbeID, "provider_id": req.ProviderID, "activation": req.Activation,
			"expected_source_ip": req.ExpectedSourceIP, "expiry_opaque": req.ExpiryOpaque,
			"arm_digest": req.ArmDigest,
		}[label]
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != size {
			return nil, fmt.Errorf("provider: invalid %s", label)
		}
	}
	pub, _ := hex.DecodeString(req.NodePublicKey)
	pubHash, _ := hex.DecodeString(req.NodePublicKeyHash)
	wantHash := sha256.Sum256(pub)
	if !bytes.Equal(pubHash, wantHash[:]) {
		return nil, errors.New("provider: node public key hash mismatch")
	}
	opaque, _ := hex.DecodeString(req.ExpiryOpaque)
	if bytes.Equal(opaque, make([]byte, protocol.ProbeOpaqueLen)) {
		return nil, errors.New("provider: expiry opaque is empty")
	}
	source, err := hex.DecodeString(req.ExpectedSourceIP)
	if err != nil || len(source) != 4 || net.IP(source).IsUnspecified() {
		return nil, errors.New("provider: invalid expected source")
	}
	if req.TTLMS == 0 || req.TTLMS > uint64(protocol.ProbeTTLMax/time.Millisecond) {
		return nil, errors.New("provider: invalid ttl")
	}
	now := nowTime.Unix()
	// The request timestamp is signed and must be recent enough that a
	// captured request cannot be replayed after its arm TTL has elapsed.
	if req.TimestampUnix < now-120 || req.TimestampUnix > now+30 {
		return nil, errors.New("provider: stale request")
	}
	canonical, err := req.canonical()
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(controllerPub, canonical, sig) {
		return nil, errors.New("provider: controller signature verification failed")
	}
	return &req, nil
}

// providerResult is the signed provider -> controller result. Accepted is
// true only after the provider verified the same-path ACK1; the WAN1 and
// ACK1 frame hex let the controller run the frozen join.
type providerResult struct {
	Schema        string `json:"schema"`
	ProbeID       string `json:"probe_id"`
	Accepted      bool   `json:"accepted"`
	ChallengeHash string `json:"challenge_hash,omitempty"`
	WAN1Frame     string `json:"wan1_frame,omitempty"`
	ACK1Frame     string `json:"ack1_frame,omitempty"`
	Reason        string `json:"reason,omitempty"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Signature     string `json:"signature"`
}

// canonical renders the exact signed bytes of the result.
func (r *providerResult) canonical() []byte {
	fields := []string{
		r.Schema, strings.ToLower(r.ProbeID),
		fmt.Sprintf("%t", r.Accepted), strings.ToLower(r.ChallengeHash),
		strings.ToLower(r.WAN1Frame), strings.ToLower(r.ACK1Frame),
		r.Reason, fmt.Sprintf("%d", r.TimestampUnix),
	}
	return []byte(strings.Join(fields, "\x00"))
}

// verify checks the provider signature against the provider public key.
func (r *providerResult) verify(providerPub ed25519.PublicKey) bool {
	if r.Schema != providerResultSchema || r.Signature == "" {
		return false
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(providerPub, r.canonical(), sig)
}

// writeProviderResult signs and writes a result.
func writeProviderResult(w http.ResponseWriter, priv ed25519.PrivateKey, res providerResult) {
	res.Schema = providerResultSchema
	res.TimestampUnix = time.Now().Unix()
	sig := ed25519.Sign(priv, res.canonical())
	res.Signature = hex.EncodeToString(sig)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
