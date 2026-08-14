// Controller probe orchestration (P10 Story 1/2 controller side).
//
// The Manager drives the two-phase arm + provider-hidden challenge flow of
// docs/protocol.md §7: it persists a probe operation, enqueues a probe_arm
// C2A command (the arm NEVER carries the challenge), waits for the durable
// probe_armed (RDY1) result through the hub's ProbeSink, then requests the
// operator-owned antinat-probe service with a controller-signed request. The
// provider performs the WAN1/ACK1 exchange; the agent's RCT1 receipt arrives
// through the sink; the Manager joins provider result + ACK + receipt with
// protocol.VerifyProbeJoin and records OPEN_FROM_VANTAGE only when the full
// join verifies.
package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// DefaultTTL bounds a probe operation (<= 24h per the frozen contract).
const DefaultTTL = 30 * time.Second

// ManagerConfig wires the probe manager.
type ManagerConfig struct {
	Store   *store.Store
	Keyring *security.Keyring
	// Clock is the wall clock (deterministic tests).
	Clock func() time.Time
	// HTTPClient for provider requests (tests inject the provider server).
	HTTPClient *http.Client
	// NodePublicKey returns the verified node public key (from the hub
	// session; the store persists only the key hash).
	NodePublicKey func(nodeID string) (ed25519.PublicKey, bool)
	// MaxProviderRounds bounds concurrent provider requests.
	MaxProviderRounds int
}

// Manager orchestrates probe operations.
type Manager struct {
	store   *store.Store
	keyring *security.Keyring
	clock   func() time.Time
	client  *http.Client
	nodeKey func(string) (ed25519.PublicKey, bool)
	rounds  chan struct{}
}

// NewManager validates config and builds the manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("probe: store is required")
	}
	if cfg.Keyring == nil {
		return nil, errors.New("probe: keyring is required")
	}
	if cfg.NodePublicKey == nil {
		return nil, errors.New("probe: node public key source is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.MaxProviderRounds <= 0 {
		cfg.MaxProviderRounds = 16
	}
	return &Manager{
		store:   cfg.Store,
		keyring: cfg.Keyring,
		clock:   cfg.Clock,
		client:  cfg.HTTPClient,
		nodeKey: cfg.NodePublicKey,
		rounds:  make(chan struct{}, cfg.MaxProviderRounds),
	}, nil
}

// Arm creates a durable probe operation and enqueues the probe_arm C2A
// command. The returned operation's ID is the probe id (hex). The arm frame
// carries the provider public key and expected source but NEVER the
// challenge.
func (m *Manager) Arm(ctx context.Context, nodeID, forwardID, activationID, endpoint string) (store.ProbeOperation, error) {
	providers, err := m.store.ListProbeProviders()
	if err != nil {
		return store.ProbeOperation{}, err
	}
	var provider *store.ProbeProvider
	for i := range providers {
		if providers[i].Enabled {
			provider = &providers[i]
			break
		}
	}
	if provider == nil {
		return store.ProbeOperation{}, errors.New("probe: no enabled provider registered")
	}

	probeID, err := randomID()
	if err != nil {
		return store.ProbeOperation{}, err
	}
	var opaque [16]byte
	if _, err := rand.Read(opaque[:]); err != nil {
		return store.ProbeOperation{}, err
	}
	providerPub, err := hex.DecodeString(provider.PublicKey)
	if err != nil || len(providerPub) != ed25519.PublicKeySize {
		return store.ProbeOperation{}, errors.New("probe: provider public key is malformed")
	}
	var providerID, activation [16]byte
	providerID = providerWireID(provider.ID)
	if b, err := hex.DecodeString(activationID); err == nil && len(b) == 16 {
		copy(activation[:], b)
	} else if activationID != "" {
		sum := sha256.Sum256([]byte("antinat-activation-v1\x00" + activationID))
		copy(activation[:], sum[:16])
	}
	var expectedSource [4]byte
	if ip := parseIPv4(provider.EgressIP); ip != nil {
		copy(expectedSource[:], ip)
	}

	arm := protocol.ProbeArm{
		ProbeID:           probeID,
		ProviderID:        providerID,
		ProviderPublicKey: [32]byte(providerPub),
		ExpectedSourceIP:  expectedSource,
		Activation:        activation,
		Endpoint:          endpoint,
		TTLMS:             uint64(DefaultTTL / time.Millisecond),
		ExpiryOpaque:      opaque,
	}
	if err := arm.Validate(); err != nil {
		return store.ProbeOperation{}, fmt.Errorf("probe: arm: %w", err)
	}

	op, err := m.store.CreateProbeOperation(store.ProbeOperation{
		ID:           hex.EncodeToString(probeID[:]),
		NodeID:       nodeID,
		ForwardID:    forwardID,
		ActivationID: activationID,
		ProviderID:   provider.ID,
		Status:       "PENDING",
		Endpoint:     endpoint,
		ArmHex:       hex.EncodeToString(arm.Canonical()),
		TTLMS:        arm.TTLMS,
		ExpiryOpaque: hex.EncodeToString(opaque[:]),
		ExpiresAt:    m.clock().Add(DefaultTTL).Unix(),
	})
	if err != nil {
		return store.ProbeOperation{}, err
	}
	if err := m.store.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID:     op.ID,
		MessageType:     "probe_arm",
		NodeID:          nodeID,
		SemanticPayload: string(arm.Canonical()),
		State:           "PENDING",
	}); err != nil {
		return store.ProbeOperation{}, err
	}
	return op, nil
}

// HandleProbeMessage implements agenthub.ProbeSink: it receives durable
// probe-plane A2C messages and advances the operation state machine.
func (m *Manager) HandleProbeMessage(nodeID, messageType string, payload []byte) error {
	switch messageType {
	case "probe_armed":
		return m.handleArmed(nodeID, payload)
	case "probe_ingress_receipt":
		return m.handleReceipt(nodeID, payload)
	case "probe_result":
		return m.handleProbeResult(nodeID, payload)
	default:
		return fmt.Errorf("probe: unexpected probe message type %q", messageType)
	}
}

// handleArmed verifies the RDY1 frame against the node key and the arm
// digest, marks the operation ARMED, and fires the provider request.
func (m *Manager) handleArmed(nodeID string, payload []byte) error {
	nodePub, ok := m.nodeKey(nodeID)
	if !ok {
		return errors.New("probe: node not online (no session key)")
	}
	// The RDY1 frame carries the arm digest; find the operation by digest.
	if _, err := protocol.ParseProbeArmed(payload, nodePub, [32]byte{}); err != nil && !errors.Is(err, protocol.ErrProbeMalformed) {
		return err
	}
	// Extract the digest from the frame (RDY1 = magic + digest + sig).
	var digest [32]byte
	if len(payload) >= 4+32 {
		copy(digest[:], payload[4:4+32])
	}
	if _, err := protocol.ParseProbeArmed(payload, nodePub, digest); err != nil {
		return fmt.Errorf("probe: probe_armed rejected: %w", err)
	}
	op, err := m.findOperationByDigest(digest)
	if err != nil {
		return err
	}
	if err := m.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		return err
	}
	// Request the provider asynchronously (bounded concurrency).
	select {
	case m.rounds <- struct{}{}:
		go func() {
			defer func() { <-m.rounds }()
			m.requestProvider(op, nodeID, nodePub)
		}()
	default:
		return m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
	}
	return nil
}

// handleReceipt stores the RCT1 frame and attempts the join.
func (m *Manager) handleReceipt(nodeID string, payload []byte) error {
	nodePub, ok := m.nodeKey(nodeID)
	if !ok {
		return errors.New("probe: node not online (no session key)")
	}
	receipt, err := protocol.ParseProbeReceipt(payload, nodePub)
	if err != nil {
		return fmt.Errorf("probe: probe_ingress_receipt rejected: %w", err)
	}
	op, err := m.findOperationByDigest(receipt.ArmDigest)
	if err != nil {
		return err
	}
	if err := m.store.RecordProbeResult(op.ID, "rct1", hex.EncodeToString(payload)); err != nil {
		return err
	}
	return m.tryJoin(op)
}

// handleProbeResult records a terminal agent-reported outcome (best-effort;
// the provider result + receipt join is authoritative).
func (m *Manager) handleProbeResult(nodeID string, payload []byte) error {
	var v struct {
		ProbeID string `json:"probe_id"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(payload, &v); err != nil || v.ProbeID == "" {
		return errors.New("probe: malformed probe_result payload")
	}
	op, err := m.store.GetProbeOperation(v.ProbeID)
	if err != nil {
		return err
	}
	if op.NodeID != nodeID {
		return errors.New("probe: probe_result node mismatch")
	}
	outcome, err := protocol.ParseProbeOutcome(v.Outcome)
	if err != nil || outcome == protocol.OutcomeArmed || outcome == protocol.OutcomeAccepted || outcome == protocol.OutcomeUnknown {
		return errors.New("probe: invalid probe_result outcome")
	}
	if op.Status == string(protocol.OutcomeOpenFromVantage) || op.Status == string(protocol.OutcomeRejected) ||
		op.Status == string(protocol.OutcomeDropped) || op.Status == string(protocol.OutcomeTimeout) ||
		op.Status == string(protocol.OutcomeNoIndependentVantage) || op.Status == string(protocol.OutcomeProbeInfraUnavailable) {
		return nil // terminal already
	}
	return m.store.SetProbeOperationStatus(op.ID, string(outcome))
}

// requestProvider sends the controller-signed provider request and records
// the result artifacts; then tries the join.
func (m *Manager) requestProvider(op store.ProbeOperation, nodeID string, nodePub ed25519.PublicKey) {
	provider, err := m.store.GetProbeProvider(op.ProviderID)
	if err != nil {
		return
	}
	armBytes, err := hex.DecodeString(op.ArmHex)
	if err != nil {
		return
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return
	}
	req := providerRequest{
		Schema:             "antinat.provider-request/v1",
		ControllerInstance: m.instanceID(),
		ControllerKeyID:    m.keyring.KeyID(),
		NodePublicKey:      hex.EncodeToString(nodePub),
		NodePublicKeyHash:  hex.EncodeToString(hash256(nodePub)),
		ProbeID:            op.ID,
		ProviderID:         hex.EncodeToString(id16Slice(providerWireID(op.ProviderID))),
		Activation:         hex.EncodeToString(arm.Activation[:]),
		Endpoint:           op.Endpoint,
		ExpectedSourceIP:   hex.EncodeToString(arm.ExpectedSourceIP[:]),
		ExpiryOpaque:       op.ExpiryOpaque,
		TTLMS:              op.TTLMS,
		ArmDigest:          hex.EncodeToString(digestSlice(arm.Digest())),
		TimestampUnix:      m.clock().Unix(),
	}
	canonical, err := req.canonical()
	if err != nil {
		return
	}
	sig, err := m.keyring.Sign(canonical)
	if err != nil {
		return
	}
	req.Signature = hex.EncodeToString(sig)

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		strings.TrimRight(provider.Endpoint, "/")+"/probe/v1/request", bytes.NewReader(body))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(httpReq)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_ = m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	var res providerResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		_ = m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	if res.ProbeID != op.ID {
		_ = m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeRejected))
		return
	}
	const resultClockSkewSeconds int64 = 5 * 60
	if res.TimestampUnix < op.CreatedAt-resultClockSkewSeconds || res.TimestampUnix > op.ExpiresAt+resultClockSkewSeconds {
		_ = m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeTimeout))
		return
	}
	providerPub, err := hex.DecodeString(provider.PublicKey)
	if err != nil {
		return
	}
	if !res.verify(providerPub) {
		return
	}
	_ = m.store.RecordProbeResult(op.ID, "provider", mustJSON(res))
	if res.WAN1Frame != "" {
		_ = m.store.RecordProbeResult(op.ID, "wan1", res.WAN1Frame)
	}
	if res.ACK1Frame != "" {
		_ = m.store.RecordProbeResult(op.ID, "ack1", res.ACK1Frame)
	}
	_ = m.store.SetProbeOperationChallenge(op.ID, res.ChallengeHash)
	if !res.Accepted {
		_ = m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeRejected))
		return
	}
	_ = m.tryJoin(op)
}

// tryJoin runs the frozen join: the provider result (WAN1+ACK1) and the
// agent receipt (RCT1) must all bind to the same operation. OPEN_FROM_VANTAGE
// is recorded only when VerifyProbeJoin passes.
func (m *Manager) tryJoin(op store.ProbeOperation) error {
	results, err := m.store.ListProbeResults(op.ID)
	if err != nil {
		return err
	}
	var wan1Hex, ack1Hex, rct1Hex string
	for _, r := range results {
		switch r.Kind {
		case "wan1":
			wan1Hex = r.PayloadHex
		case "ack1":
			ack1Hex = r.PayloadHex
		case "rct1":
			rct1Hex = r.PayloadHex
		}
	}
	if wan1Hex == "" || ack1Hex == "" || rct1Hex == "" {
		return nil // not all artifacts joined yet
	}
	armBytes, err := hex.DecodeString(op.ArmHex)
	if err != nil {
		return err
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return err
	}
	wan1, err := hex.DecodeString(wan1Hex)
	if err != nil {
		return err
	}
	frame, err := protocol.ParseProviderFrame(wan1)
	if err != nil {
		return err
	}
	ack1, err := hex.DecodeString(ack1Hex)
	if err != nil {
		return err
	}
	nodePub, ok := m.nodeKey(op.NodeID)
	if !ok {
		return errors.New("probe: node session lost before join")
	}
	ack, err := protocol.ParseProbeACK(ack1, nodePub)
	if err != nil {
		return err
	}
	rct1, err := hex.DecodeString(rct1Hex)
	if err != nil {
		return err
	}
	receipt, err := protocol.ParseProbeReceipt(rct1, nodePub)
	if err != nil {
		return err
	}
	if !protocol.VerifyProbeJoin(arm, frame, ack, receipt, nodePub) {
		return m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeRejected))
	}
	if err := m.store.SetProbeOperationStatus(op.ID, string(protocol.OutcomeOpenFromVantage)); err != nil {
		return err
	}
	// Mirror the verified orthogonal snapshot so the admin API forward view
	// shows OPEN_FROM_VANTAGE / PUBLISHED_VERIFIED (Story 3 publication).
	snapshot := protocol.ActivationStates{
		ControlState:         "ONLINE",
		ListenerState:        "ACTIVE",
		MappingState:         "NOT_REQUIRED",
		KeepaliveState:       "NOT_REQUIRED",
		WanReachabilityState: string(protocol.OutcomeOpenFromVantage),
		ReturnPathState:      "VERIFIED",
		TargetHealthState:    "UNKNOWN",
		PublicationState:     "PUBLISHED_VERIFIED",
		DataPlaneState:       "ACTIVE",
	}
	raw, _ := json.Marshal(snapshot)
	return m.store.SetForwardRuntimeStatus(op.ForwardID, op.ActivationID, string(raw))
}

// findOperationByDigest scans pending/armed operations for the arm digest.
// The digest uniquely identifies the arm; the operation row carries the arm
// hex, so a full scan is bounded by active probe count (small).
func (m *Manager) findOperationByDigest(digest [32]byte) (store.ProbeOperation, error) {
	return m.scanOperationByDigest(digest)
}

// scanOperationByDigest finds the operation whose arm digest matches.
func (m *Manager) scanOperationByDigest(digest [32]byte) (store.ProbeOperation, error) {
	// The store does not index arm digests; the probe operation set is
	// bounded by the operation TTL, so a linear scan is acceptable here.
	return m.store.ProbeOperationByArmDigest(digest)
}

func (m *Manager) instanceID() string {
	id, err := m.store.InstanceID()
	if err != nil {
		return ""
	}
	return id
}

func randomID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}

func parseIPv4(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// providerWireID derives the fixed 16-byte provider id from the operator-
// chosen text id (hex ids pass through; text ids are hashed).
func providerWireID(id string) [16]byte {
	var out [16]byte
	if b, err := hex.DecodeString(id); err == nil && len(b) == 16 {
		copy(out[:], b)
		return out
	}
	sum := sha256.Sum256([]byte("antinat-provider-v1\x00" + id))
	copy(out[:], sum[:16])
	return out
}

// hash256 returns the sha256 of b as a slice.
func hash256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// digestSlice returns a 32-byte digest as a slice.
func digestSlice(d [32]byte) []byte {
	return d[:]
}

// id16Slice returns a 16-byte id as a slice.
func id16Slice(d [16]byte) []byte {
	return d[:]
}

func mustJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
