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
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
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
	// MaxActiveOperations bounds live durable probe operations.
	MaxActiveOperations int
	// SweepInterval controls expiry and result-retention sweeps.
	SweepInterval time.Duration
	// ResultRetention bounds terminal probe artifacts.
	ResultRetention time.Duration
	// CleanupBatchSize bounds rows transitioned/deleted by one sweeper pass.
	CleanupBatchSize int
}

// Manager orchestrates probe operations.
type Manager struct {
	store           *store.Store
	keyring         *security.Keyring
	clock           func() time.Time
	client          *http.Client
	nodeKey         func(string) (ed25519.PublicKey, bool)
	rounds          chan struct{}
	maxActive       int
	sweepInterval   time.Duration
	resultRetention time.Duration
	cleanupBatch    int
	mu              sync.Mutex
	active          map[string]struct{}
	armMu           sync.Mutex
	terminalMu      sync.Mutex
	terminalAfter   int64
	terminalAfterID string
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	workWG          sync.WaitGroup
	closed          bool
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
	if cfg.MaxActiveOperations <= 0 {
		cfg.MaxActiveOperations = 1024
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = 500 * time.Millisecond
	}
	if cfg.ResultRetention <= 0 {
		cfg.ResultRetention = 24 * time.Hour
	}
	if cfg.CleanupBatchSize <= 0 {
		cfg.CleanupBatchSize = 256
	}
	cfg.Store.SetClock(cfg.Clock)
	return &Manager{
		store:           cfg.Store,
		keyring:         cfg.Keyring,
		clock:           cfg.Clock,
		client:          cfg.HTTPClient,
		nodeKey:         cfg.NodePublicKey,
		rounds:          make(chan struct{}, cfg.MaxProviderRounds),
		maxActive:       cfg.MaxActiveOperations,
		sweepInterval:   cfg.SweepInterval,
		resultRetention: cfg.ResultRetention,
		cleanupBatch:    cfg.CleanupBatchSize,
		active:          make(map[string]struct{}),
	}, nil
}

// Start launches the cancellable expiry/result sweeper. It is safe to omit
// Start in focused unit tests; request paths then use a per-operation context.
func (m *Manager) Start(parent context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return errors.New("probe: manager already started")
	}
	if parent == nil {
		parent = context.Background()
	}
	m.ctx, m.cancel = context.WithCancel(parent)
	m.closed = false
	m.wg.Add(1)
	ctx := m.ctx
	m.mu.Unlock()
	go m.sweepLoop(ctx)
	m.recoverOperations()
	return nil
}

// Close cancels the sweeper and waits for all manager-owned work to finish.
func (m *Manager) Close() error {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.closed = true
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	m.workWG.Wait()
	m.mu.Lock()
	if m.cancel == nil {
		m.ctx = nil
	}
	m.mu.Unlock()
	return nil
}

// sweepLoop runs expiry and retention GC until Close cancels the manager.
func (m *Manager) sweepLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.sweepOnce(m.clock())
			m.recoverOperations()
		}
	}
}

// sweepOnce performs one bounded lifecycle pass. The cadence is real-time,
// but all expiry/retention decisions use the injected Manager clock so tests
// and operators can reason about exact boundaries without sleeps.
func (m *Manager) sweepOnce(at time.Time) error {
	nowUnix := at.Unix()
	expired, err := m.store.ExpireProbeOperationsLimit(nowUnix, m.cleanupBatch)
	if err != nil {
		return err
	}
	for _, op := range expired {
		_ = m.enqueueActivationOutcome(op.ID, protocol.OutcomeTimeout)
	}
	cutoff := at.Add(-m.resultRetention).Unix()
	if _, err := m.store.ExpireTerminalProbeDeliveriesBeforeLimit(cutoff, m.cleanupBatch); err != nil {
		return err
	}
	if _, err := m.store.DeleteProbeResultsBeforeLimit(cutoff, m.cleanupBatch); err != nil {
		return err
	}
	if _, err := m.store.DeleteTerminalProbeOperationsBeforeLimit(cutoff, m.cleanupBatch); err != nil {
		return err
	}
	// Control inbox rows are message-id replay state. They expire on the
	// protocol replay window, independently of the longer probe audit window.
	if _, err := m.store.DeleteControlInboxBeforeLimit(at.Add(-protocol.ProbeReplayWindow).Unix(), m.cleanupBatch); err != nil {
		return err
	}
	return nil
}

// startProvider reserves one provider round and records ownership before the
// goroutine starts. The active map prevents a recovery sweep from launching a
// duplicate request while the original request is still live.
func (m *Manager) startProvider(op store.ProbeOperation, nodeID string, nodePub ed25519.PublicKey) bool {
	m.mu.Lock()
	if _, ok := m.active[op.ID]; ok {
		m.mu.Unlock()
		return true
	}
	if m.closed {
		m.mu.Unlock()
		return false
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		m.mu.Unlock()
		return false
	}
	select {
	case m.rounds <- struct{}{}:
	default:
		m.mu.Unlock()
		return false
	}
	m.active[op.ID] = struct{}{}
	m.workWG.Add(1)
	m.mu.Unlock()
	go func(requestCtx context.Context) {
		defer m.workWG.Done()
		defer func() { <-m.rounds }()
		defer func() {
			m.mu.Lock()
			delete(m.active, op.ID)
			m.mu.Unlock()
		}()
		m.requestProvider(requestCtx, op, nodeID, nodePub)
	}(ctx)
	return true
}

// recoverOperations rehydrates live ARMED and interrupted IN_FLIGHT work
// after a controller restart. Node keys are intentionally read from the live
// hub session; if a node is offline the ARMED row remains durable and is
// picked up by the next reconnect/recovery pass.
func (m *Manager) recoverOperations() {
	m.recoverTerminalOutcomes()
	ops, err := m.store.ListProbeOperationsByStatusLimit(m.maxActive, "ARMED", "IN_FLIGHT")
	if err != nil {
		return
	}
	for _, op := range ops {
		if !m.clock().Before(time.Unix(op.ExpiresAt, 0)) {
			_ = m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
			continue
		}
		m.mu.Lock()
		_, active := m.active[op.ID]
		m.mu.Unlock()
		if active {
			continue
		}
		if op.Status == "IN_FLIGHT" {
			if err := m.store.RequeueProbeOperationForRecovery(op.ID); err != nil {
				continue
			}
			op.Status = "ARMED"
		}
		nodePub, ok := m.nodeKey(op.NodeID)
		if !ok {
			continue
		}
		provider, err := m.store.GetProbeProvider(op.ProviderID)
		if err != nil {
			continue
		}
		if !provider.IndependentVantage {
			_ = m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeNoIndependentVantage)
			continue
		}
		_ = m.startProvider(op, op.NodeID, nodePub)
	}
}

// recoverTerminalOutcomes repairs at most one caller-budgeted page per sweep.
// The cursor is manager-owned and serialized so concurrent reconnect/sweeper
// calls cannot turn a bounded page into duplicate full-history walks.
func (m *Manager) recoverTerminalOutcomes() {
	m.terminalMu.Lock()
	defer m.terminalMu.Unlock()
	ops, err := m.store.ListUndeliveredTerminalProbeOperationsPage(m.cleanupBatch, m.terminalAfter, m.terminalAfterID)
	if err != nil {
		return
	}
	if len(ops) == 0 {
		m.terminalAfter, m.terminalAfterID = 0, ""
		return
	}
	for _, op := range ops {
		acked, err := m.store.ProbeOutcomeAcknowledged(op.ID)
		if err != nil {
			return
		}
		if !acked {
			_ = m.enqueueActivationOutcome(op.ID, protocol.ProbeOutcome(op.Status))
		}
		m.terminalAfter, m.terminalAfterID = op.CreatedAt, op.ID
	}
	if len(ops) < m.cleanupBatch {
		m.terminalAfter, m.terminalAfterID = 0, ""
	}
}

// Arm creates a durable probe operation and enqueues the probe_arm C2A
// command. The returned operation's ID is the probe id (hex). The arm frame
// carries the provider public key and expected source but NEVER the
// challenge.
func (m *Manager) Arm(ctx context.Context, nodeID, forwardID, activationID, endpoint string) (store.ProbeOperation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return store.ProbeOperation{}, ctx.Err()
	default:
	}
	forward, err := m.store.GetForward(forwardID)
	if err != nil {
		return store.ProbeOperation{}, err
	}
	if forward.NodeID != nodeID {
		return store.ProbeOperation{}, errors.New("probe: forward is bound to a different node")
	}
	if forward.CurrentActivationID == "" {
		return store.ProbeOperation{}, errors.New("probe: forward has no current activation")
	}
	if forward.CurrentActivationID != activationID {
		return store.ProbeOperation{}, errors.New("probe: activation is stale for forward")
	}
	m.armMu.Lock()
	defer m.armMu.Unlock()
	live, err := m.store.CountLiveProbeOperationsAt(m.clock().Unix())
	if err != nil {
		return store.ProbeOperation{}, err
	}
	if live >= m.maxActive {
		return store.ProbeOperation{}, errors.New("probe: active operation limit reached")
	}
	providers, err := m.store.ListProbeProviders()
	if err != nil {
		return store.ProbeOperation{}, err
	}
	var provider *store.ProbeProvider
	for i := range providers {
		if !providers[i].Enabled {
			continue
		}
		if provider == nil {
			provider = &providers[i]
		}
		if providers[i].IndependentVantage {
			provider = &providers[i]
			break
		}
	}
	if provider == nil {
		return store.ProbeOperation{}, errors.New("probe: no enabled provider registered")
	}
	// A probe join is allowed to mutate only an already-persisted activation
	// mirror. Initialize the legal pre-probe baseline at arm time rather than
	// fabricating unrelated axes from WAN evidence during the join transaction.
	if _, err := m.store.GetForwardRuntimeStatus(forwardID); errors.Is(err, store.ErrNotFound) {
		baseline := protocol.ActivationStates{
			ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
			KeepaliveState: "NOT_REQUIRED", WanReachabilityState: "NOT_TESTED",
			ReturnPathState: "NOT_TESTED", TargetHealthState: "UNKNOWN",
			PublicationState: "NONE", DataPlaneState: "READY",
		}
		rawBaseline, marshalErr := json.Marshal(baseline)
		if marshalErr != nil {
			return store.ProbeOperation{}, marshalErr
		}
		if err := m.store.SetForwardRuntimeStatus(forwardID, activationID, string(rawBaseline)); err != nil {
			return store.ProbeOperation{}, fmt.Errorf("probe: initialize runtime mirror: %w", err)
		}
	} else if err != nil {
		return store.ProbeOperation{}, fmt.Errorf("probe: read runtime mirror: %w", err)
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
	sourceAddr, err := netip.ParseAddr(provider.EgressIP)
	if err != nil || !sourceAddr.Is4() || !protocol.IsGlobalEndpoint(sourceAddr) {
		return store.ProbeOperation{}, errors.New("probe: provider egress IP is not a global IPv4 literal")
	}
	sourceBytes := sourceAddr.As4()
	copy(expectedSource[:], sourceBytes[:])

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

	op, err := m.store.CreateProbeOperationBundle(store.ProbeOperation{
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
	}, store.ControlOutboxItem{
		OperationID:     hex.EncodeToString(probeID[:]),
		MessageType:     "probe_arm",
		NodeID:          nodeID,
		SemanticPayload: string(arm.Canonical()),
		State:           "PENDING",
	})
	if err != nil {
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

// HandleActivationStatus consumes an agent evidence-loss status and updates
// the controller runtime mirror under the current activation CAS.
func (m *Manager) HandleActivationStatus(nodeID string, payload []byte) error {
	var v struct {
		ForwardID  string                    `json:"forward_id"`
		Activation string                    `json:"activation"`
		Generation uint64                    `json:"generation"`
		Snapshot   protocol.ActivationStates `json:"snapshot"`
	}
	if err := protocol.DecodeStrictJSONInto(payload, &v); err != nil || v.ForwardID == "" || v.Activation == "" {
		return errors.New("probe: malformed activation status")
	}
	if err := v.Snapshot.Validate(); err != nil {
		return fmt.Errorf("probe: invalid activation status: %w", err)
	}
	forward, err := m.store.GetForward(v.ForwardID)
	if err != nil {
		return err
	}
	if forward.NodeID != nodeID || forward.CurrentActivationID != v.Activation ||
		v.Generation == 0 || v.Generation != forward.Revision {
		return store.ErrCASConflict
	}
	stateJSON, err := json.Marshal(v.Snapshot)
	if err != nil {
		return err
	}
	return m.store.SetForwardRuntimeStatus(v.ForwardID, v.Activation, string(stateJSON))
}

// handleArmed verifies the RDY1 frame against the node key and the arm
// digest, marks the operation ARMED, and fires the provider request.
func (m *Manager) handleArmed(nodeID string, payload []byte) error {
	nodePub, ok := m.nodeKey(nodeID)
	if !ok {
		return errors.New("probe: node not online (no session key)")
	}
	if len(payload) != 4+32+ed25519.SignatureSize {
		return errors.New("probe: malformed probe_armed frame")
	}
	var digest [32]byte
	copy(digest[:], payload[4:4+32])
	if _, err := protocol.ParseProbeArmed(payload, nodePub, digest); err != nil {
		return fmt.Errorf("probe: probe_armed rejected: %w", err)
	}
	op, err := m.store.ProbeOperationByArmDigestForNode(digest, nodeID, m.clock().Unix())
	if err != nil {
		return err
	}
	if m.clock().Unix() >= op.ExpiresAt {
		return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
	}
	if err := m.store.SetProbeOperationStatusCAS(op.ID, "PENDING", "ARMED"); err != nil {
		if errors.Is(err, store.ErrProbeTerminal) {
			return nil
		}
		return err
	}
	provider, err := m.store.GetProbeProvider(op.ProviderID)
	if err != nil {
		_ = m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeProbeInfraUnavailable)
		return err
	}
	if !provider.IndependentVantage {
		return m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeNoIndependentVantage)
	}
	// Request the provider asynchronously (bounded concurrency).
	if !m.startProvider(op, nodeID, nodePub) {
		return m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeProbeInfraUnavailable)
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
	op, err := m.store.ProbeOperationByArmDigestForNodeIncludingExpired(receipt.ArmDigest, nodeID)
	if err != nil {
		return err
	}
	if !m.clock().Before(time.Unix(op.ExpiresAt, 0)) {
		if op.Status == "ARMED" || op.Status == "IN_FLIGHT" || op.Status == "PENDING" {
			return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
		}
		return nil
	}
	if op.Status != "ARMED" && op.Status != "IN_FLIGHT" {
		return nil // late receipts cannot resurrect a terminal operation
	}
	if err := m.store.RecordProbeResult(op.ID, "rct1", hex.EncodeToString(payload)); err != nil {
		if errors.Is(err, store.ErrProbeExpired) {
			return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
		}
		if errors.Is(err, store.ErrProbeDuplicateEvidence) {
			m.failOperation(op.ID, string(protocol.OutcomeRejected))
		}
		return err
	}
	return m.tryJoin(op)
}

// handleProbeResult records a terminal agent-reported outcome (best-effort;
// the provider result + receipt join is authoritative).
func (m *Manager) handleProbeResult(nodeID string, payload []byte) error {
	v, err := decodeProbeResultJSON(payload)
	if err != nil || v.ProbeID == "" {
		return errors.New("probe: malformed probe_result payload")
	}
	outcome, err := protocol.ParseProbeOutcome(v.Outcome)
	if err != nil || outcome == protocol.OutcomeArmed || outcome == protocol.OutcomeAccepted ||
		outcome == protocol.OutcomeOpenFromVantage || outcome == protocol.OutcomeUnknown {
		return errors.New("probe: invalid probe_result outcome")
	}
	op, err := m.store.GetProbeOperation(v.ProbeID)
	if err != nil {
		return err
	}
	if op.NodeID != nodeID || op.Status == string(protocol.OutcomeOpenFromVantage) || op.Status == string(protocol.OutcomeRejected) ||
		op.Status == string(protocol.OutcomeDropped) || op.Status == string(protocol.OutcomeTimeout) ||
		op.Status == string(protocol.OutcomeNoIndependentVantage) || op.Status == string(protocol.OutcomeProbeInfraUnavailable) {
		return nil // terminal already
	}
	if !m.clock().Before(time.Unix(op.ExpiresAt, 0)) {
		return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
	}
	if op.Status != "ARMED" && op.Status != "IN_FLIGHT" && op.Status != "PENDING" {
		return errors.New("probe: probe_result is not bound to a live operation")
	}
	return m.setTerminalOutcome(op.ID, op.Status, outcome)
}

// providerFailureOutcome maps provider transport/admission taxonomy to the
// durable probe outcome registry. A pending admission is deliberately
// non-terminal: recovery retries the still-IN_FLIGHT operation.
func providerFailureOutcome(reason string) (string, bool) {
	switch strings.ToLower(reason) {
	case "pending", "busy", "replay", "rate_limited":
		return "", false
	case "timeout":
		return string(protocol.OutcomeTimeout), true
	case "unreachable", "no_ack", "send_failed", "challenge_unavailable", "invalid_source", "deadline_failed":
		return string(protocol.OutcomeProbeInfraUnavailable), true
	default:
		return string(protocol.OutcomeRejected), true
	}
}

// requestProvider sends the controller-signed provider request and records
// the result artifacts; then tries the join.
func (m *Manager) requestProvider(requestCtx context.Context, op store.ProbeOperation, nodeID string, nodePub ed25519.PublicKey) {
	provider, err := m.store.GetProbeProvider(op.ProviderID)
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	if !provider.IndependentVantage {
		m.failOperation(op.ID, string(protocol.OutcomeNoIndependentVantage))
		return
	}
	deadline := time.Unix(op.ExpiresAt, 0)
	if !m.clock().Before(deadline) {
		m.failOperation(op.ID, string(protocol.OutcomeTimeout))
		return
	}
	ctx, cancel := context.WithDeadline(requestCtx, deadline)
	defer cancel()
	if err := m.store.SetProbeOperationStatusCAS(op.ID, "ARMED", "IN_FLIGHT"); err != nil {
		return
	}
	armBytes, err := hex.DecodeString(op.ArmHex)
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeRejected))
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
		TimestampUnix:      op.CreatedAt,
	}
	canonical, err := req.canonical()
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeRejected))
		return
	}
	sig, err := m.keyring.Sign(canonical)
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	req.Signature = hex.EncodeToString(sig)

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(provider.Endpoint, "/")+"/probe/v1/request", bytes.NewReader(body))
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || !m.clock().Before(deadline) {
			m.failOperation(op.ID, string(protocol.OutcomeTimeout))
		} else {
			m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	const maxProviderResponseBytes = int64(protocol.MaxPayloadBytes)
	if resp.ContentLength > maxProviderResponseBytes {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponseBytes+1))
	if err != nil || int64(len(bodyBytes)) > maxProviderResponseBytes {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	res, err := decodeProviderResultJSON(bodyBytes)
	if err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	if res.ProbeID != op.ID {
		m.failOperation(op.ID, string(protocol.OutcomeRejected))
		return
	}
	const resultClockSkewSeconds int64 = 5 * 60
	if res.TimestampUnix < op.CreatedAt-resultClockSkewSeconds || res.TimestampUnix > op.ExpiresAt+resultClockSkewSeconds {
		m.failOperation(op.ID, string(protocol.OutcomeTimeout))
		return
	}
	providerPub, err := hex.DecodeString(provider.PublicKey)
	if err != nil || len(providerPub) != ed25519.PublicKeySize {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	if !res.verify(providerPub) {
		m.failOperation(op.ID, string(protocol.OutcomeRejected))
		return
	}
	if !res.Accepted {
		if status, terminal := providerFailureOutcome(res.Reason); terminal {
			m.failOperation(op.ID, status)
		}
		// pending/busy are transient admission results. Keep the operation in
		// IN_FLIGHT so recovery requeues it instead of manufacturing REJECTED.
		return
	}
	if err := m.store.RecordProbeResult(op.ID, "provider", mustJSON(res)); err != nil {
		if errors.Is(err, store.ErrProbeDuplicateEvidence) {
			_ = m.tryJoin(op)
			return
		}
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	if res.WAN1Frame != "" {
		if err := m.store.RecordProbeResult(op.ID, "wan1", res.WAN1Frame); err != nil {
			if errors.Is(err, store.ErrProbeDuplicateEvidence) {
				_ = m.tryJoin(op)
				return
			}
			m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
			return
		}
	}
	if res.ACK1Frame != "" {
		if err := m.store.RecordProbeResult(op.ID, "ack1", res.ACK1Frame); err != nil {
			if errors.Is(err, store.ErrProbeDuplicateEvidence) {
				_ = m.tryJoin(op)
				return
			}
			m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
			return
		}
	}
	if err := m.store.SetProbeOperationChallenge(op.ID, res.ChallengeHash); err != nil {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return
	}
	if !res.Accepted {
		m.failOperation(op.ID, string(protocol.OutcomeRejected))
		return
	}
	if res.ChallengeHash == "" || res.WAN1Frame == "" || res.ACK1Frame == "" {
		m.failOperation(op.ID, string(protocol.OutcomeRejected))
		return
	}
	if err := m.tryJoin(op); err != nil {
		if errors.Is(err, store.ErrProbeExpired) {
			m.failOperation(op.ID, string(protocol.OutcomeTimeout))
		} else {
			m.failOperation(op.ID, string(protocol.OutcomeRejected))
		}
	}
}

// tryJoin runs the frozen join: the provider result (WAN1+ACK1) and the
// agent receipt (RCT1) must all bind to the same operation. OPEN_FROM_VANTAGE
// is recorded only when VerifyProbeJoin passes.
func (m *Manager) tryJoin(op store.ProbeOperation) error {
	current, err := m.store.GetProbeOperation(op.ID)
	if err != nil {
		return err
	}
	if current.Status != "IN_FLIGHT" {
		return nil
	}
	if m.clock().Unix() >= current.ExpiresAt {
		m.failOperation(op.ID, string(protocol.OutcomeTimeout))
		return nil
	}
	results, err := m.store.ListProbeResults(op.ID)
	if err != nil {
		return err
	}
	var providerJSON, wan1Hex, ack1Hex, rct1Hex string
	for _, r := range results {
		switch r.Kind {
		case "provider":
			if providerJSON != "" {
				return m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected)
			}
			providerJSON = r.PayloadHex
		case "wan1":
			wan1Hex = r.PayloadHex
		case "ack1":
			ack1Hex = r.PayloadHex
		case "rct1":
			rct1Hex = r.PayloadHex
		}
	}
	if providerJSON == "" || wan1Hex == "" || ack1Hex == "" || rct1Hex == "" {
		return nil // not all artifacts joined yet
	}
	reject := func(cause error) error {
		_ = m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected)
		return cause
	}
	providerRes, err := decodeProviderResultJSON([]byte(providerJSON))
	if err != nil || !providerRes.Accepted || providerRes.ProbeID != current.ID || providerRes.ChallengeHash == "" {
		return m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected)
	}
	armBytes, err := hex.DecodeString(current.ArmHex)
	if err != nil {
		return reject(err)
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return reject(err)
	}
	wan1, err := hex.DecodeString(wan1Hex)
	if err != nil {
		return reject(err)
	}
	frame, err := protocol.ParseProviderFrame(wan1)
	if err != nil {
		return reject(err)
	}
	frameChallenge := frame.ChallengeHash()
	frameChallengeHex := hex.EncodeToString(frameChallenge[:])
	if current.ChallengeHash == "" || !strings.EqualFold(current.ChallengeHash, providerRes.ChallengeHash) ||
		!strings.EqualFold(providerRes.ChallengeHash, frameChallengeHex) {
		return m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected)
	}
	ack1, err := hex.DecodeString(ack1Hex)
	if err != nil {
		return reject(err)
	}
	nodePub, ok := m.nodeKey(current.NodeID)
	if !ok {
		m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
		return errors.New("probe: node session lost before join")
	}
	ack, err := protocol.ParseProbeACK(ack1, nodePub)
	if err != nil {
		return reject(err)
	}
	rct1, err := hex.DecodeString(rct1Hex)
	if err != nil {
		return reject(err)
	}
	receipt, err := protocol.ParseProbeReceipt(rct1, nodePub)
	if err != nil {
		return reject(err)
	}
	if !protocol.VerifyProbeJoin(arm, frame, ack, receipt, nodePub) {
		return m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected)
	}
	// Mirror a complete legal orthogonal snapshot. ACTIVE/READY are listener
	// state values; OPEN_FROM_VANTAGE is evidence, not a listener state.
	snapshot := protocol.ActivationStates{
		ControlState:         "ONLINE",
		ListenerState:        "READY",
		MappingState:         "PUBLIC_CANDIDATE",
		KeepaliveState:       "HEALTHY",
		WanReachabilityState: string(protocol.OutcomeOpenFromVantage),
		ReturnPathState:      "VERIFIED",
		TargetHealthState:    "PASS",
		PublicationState:     "PUBLISHED_VERIFIED",
		DataPlaneState:       "READY",
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(snapshot)
	if err := m.store.PublishProbeJoin(op.ID, "IN_FLIGHT", current.ForwardID, current.ActivationID, string(raw), nodePub); err != nil {
		if errors.Is(err, store.ErrProbeExpired) {
			m.failOperation(op.ID, string(protocol.OutcomeTimeout))
		} else {
			m.failOperation(op.ID, string(protocol.OutcomeRejected))
		}
		return err
	}
	if err := m.enqueueActivationOutcome(op.ID, protocol.OutcomeOpenFromVantage); err != nil {
		return fmt.Errorf("probe: persist activation outcome: %w", err)
	}
	return nil
}

// enqueueActivationOutcome durably joins the terminal controller result to the
// agent's current activation. Reusing the same operation is idempotent, while
// a mismatched activation is rejected by the forward CAS fence.
func (m *Manager) enqueueActivationOutcome(operationID string, outcome protocol.ProbeOutcome) error {
	_, err := m.store.QueueProbeOutcome(operationID, outcome)
	return err
}

// setTerminalOutcome advances a terminal probe result and queues the matching
// agent activation command. The two durable records are separate SQLite
// transactions, so callers can retry the queue step without changing status.
func (m *Manager) setTerminalOutcome(operationID, expected string, outcome protocol.ProbeOutcome) error {
	if err := m.store.SetProbeOperationStatusCAS(operationID, expected, string(outcome)); err != nil {
		return err
	}
	return m.enqueueActivationOutcome(operationID, outcome)
}

// failOperation moves a live operation to a terminal status without allowing
// a late provider goroutine to overwrite a sweeper decision.
func (m *Manager) failOperation(id, status string) {
	op, err := m.store.GetProbeOperation(id)
	if err != nil || op.Status == status {
		return
	}
	if op.Status == string(protocol.OutcomeOpenFromVantage) || op.Status == string(protocol.OutcomeRejected) ||
		op.Status == string(protocol.OutcomeDropped) || op.Status == string(protocol.OutcomeTimeout) ||
		op.Status == string(protocol.OutcomeNoIndependentVantage) || op.Status == string(protocol.OutcomeProbeInfraUnavailable) {
		return
	}
	_ = m.setTerminalOutcome(id, op.Status, protocol.ProbeOutcome(status))
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
