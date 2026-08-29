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
const (
	DefaultTTL          = 30 * time.Second
	maxBackgroundErrors = 64
)

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
	lifecycleMu     sync.Mutex
	// closing and closeDone describe one manager-owned shutdown cycle. The
	// cycle is single-flight so a caller whose context expires can return while
	// a later caller joins the same finalizer instead of racing another drain.
	closing         bool
	closeDone       chan struct{}
	mu              sync.Mutex
	active          map[string]struct{}
	armMu           sync.Mutex
	recoveryMu      sync.Mutex
	recoveryAfter   int64
	recoveryAfterID string
	terminalMu      sync.Mutex
	terminalAfter   int64
	terminalAfterID string
	backgroundErrMu sync.Mutex
	backgroundErrs  []error
	// beforeRecordProbeResult is a deterministic test seam for the live receipt
	// versus terminal-outcome race. Production leaves it nil.
	beforeRecordProbeResult func(operationID, kind, payloadHex string)
	ctx                     context.Context
	cancel                  context.CancelFunc
	wg                      sync.WaitGroup
	workWG                  sync.WaitGroup
	closed                  bool
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
// If a close cycle is active, Start waits for that cycle to drain before it
// installs a new sweeper. The caller's parent context bounds that wait.
func (m *Manager) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	for {
		m.lifecycleMu.Lock()
		if m.closing {
			done := m.closeDone
			m.lifecycleMu.Unlock()
			select {
			case <-done:
				continue
			case <-parent.Done():
				return parent.Err()
			}
		}

		m.mu.Lock()
		if m.cancel != nil {
			m.mu.Unlock()
			m.lifecycleMu.Unlock()
			return errors.New("probe: manager already started")
		}
		m.ctx, m.cancel = context.WithCancel(parent)
		m.closed = false
		m.wg.Add(1)
		ctx := m.ctx
		m.mu.Unlock()
		go m.sweepLoop(ctx)
		if err := m.recoverOperations(); err != nil {
			m.recordBackgroundError(err)
		}
		m.lifecycleMu.Unlock()
		return nil
	}
}

// Close cancels the sweeper and waits for all manager-owned work to finish.
// It uses a background context, so it delegates to the same single-flight
// shutdown cycle as bounded callers.
func (m *Manager) Close() error {
	return m.CloseContext(context.Background())
}

// CloseContext begins (or joins) one manager-owned shutdown cycle. Cancellation
// only bounds this caller's wait: the finalizer continues joining the sweeper
// and provider rounds, preserving active/round ownership and any IN_FLIGHT
// operation for restart recovery. A later caller can join closeDone.
func (m *Manager) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.lifecycleMu.Lock()
	if m.closing {
		done := m.closeDone
		m.lifecycleMu.Unlock()
		return waitManagerClose(ctx, done)
	}
	m.closing = true
	m.closeDone = make(chan struct{})
	done := m.closeDone
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.closed = true
	m.mu.Unlock()
	m.lifecycleMu.Unlock()

	go m.finishClose(done, cancel)
	return waitManagerClose(ctx, done)
}

func waitManagerClose(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) finishClose(done chan struct{}, cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	m.workWG.Wait()
	m.recoveryMu.Lock()
	m.recoveryAfter, m.recoveryAfterID = 0, ""
	m.recoveryMu.Unlock()
	m.mu.Lock()
	if m.cancel == nil {
		m.ctx = nil
	}
	m.mu.Unlock()

	m.lifecycleMu.Lock()
	m.closing = false
	close(done)
	m.lifecycleMu.Unlock()
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
			// Each lifecycle pass is itself bounded and durable. A failed
			// pass must not stop the sweeper: the next tick retries the same
			// status/delivery boundary, while the error is retained for the
			// manager's caller-visible diagnostics.
			if err := m.sweepOnce(m.clock()); err != nil {
				m.recordBackgroundError(err)
			}
			if err := m.recoverOperations(); err != nil {
				m.recordBackgroundError(err)
			}
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
		if err := m.enqueueActivationOutcome(op.ID, protocol.OutcomeTimeout); err != nil {
			return fmt.Errorf("probe: enqueue timeout outcome %q: %w", op.ID, err)
		}
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

// Provider-round admission errors are deliberately distinct from provider
// execution failures. Capacity and lifecycle cancellation leave an ARMED row
// retryable; they are not evidence that the probe infrastructure rejected it.
var (
	errProviderRoundCapacity = errors.New("probe: provider round capacity unavailable")
	errProviderManagerClosed = errors.New("probe: manager is not accepting provider rounds")
)

// startProvider reserves one provider round and records ownership before the
// goroutine starts. The active map prevents a recovery sweep from launching a
// duplicate request while the original request is still live.
func (m *Manager) startProvider(op store.ProbeOperation, nodeID string, nodePub ed25519.PublicKey) error {
	m.mu.Lock()
	if _, ok := m.active[op.ID]; ok {
		m.mu.Unlock()
		return nil
	}
	if m.closed {
		m.mu.Unlock()
		return errProviderManagerClosed
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		m.mu.Unlock()
		return fmt.Errorf("%w: %v", errProviderManagerClosed, ctx.Err())
	}
	select {
	case m.rounds <- struct{}{}:
	default:
		m.mu.Unlock()
		return errProviderRoundCapacity
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
		if err := m.requestProvider(requestCtx, op, nodeID, nodePub); err != nil {
			m.recordBackgroundError(err)
		}
	}(ctx)
	return nil
}

// recoverOperations rehydrates live ARMED and interrupted IN_FLIGHT work
// after a controller restart. Node keys are intentionally read from the live
// hub session; if a node is offline the ARMED row remains durable and is
// picked up by the next reconnect/recovery pass.
func (m *Manager) recoverOperations() error {
	var recoveryErrs []error
	if err := m.recoverTerminalOutcomes(); err != nil {
		recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: recover terminal outcomes: %w", err))
	}
	now := m.clock()
	// Expire the bounded historical backlog first, then enumerate only rows
	// that are still live for recovery. Keeping these pages separate prevents
	// old ARMED/IN_FLIGHT rows from consuming the active recovery budget and
	// hiding newer work.
	expired, err := m.store.ExpireProbeOperationsLimit(now.Unix(), m.cleanupBatch)
	if err != nil {
		recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: expire operations during recovery: %w", err))
	} else {
		for _, op := range expired {
			if err := m.enqueueActivationOutcome(op.ID, protocol.OutcomeTimeout); err != nil {
				recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: enqueue recovered timeout outcome %q: %w", op.ID, err))
			}
		}
	}
	ops, err := m.listRecoveryOperations(now.Unix())
	if err != nil {
		recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: list live operations for recovery: %w", err))
		return errors.Join(recoveryErrs...)
	}
	for _, op := range ops {
		m.mu.Lock()
		_, active := m.active[op.ID]
		m.mu.Unlock()
		if active {
			continue
		}
		nodePub, nodeKeyOK := m.nodeKey(op.NodeID)
		if op.Status == "IN_FLIGHT" {
			// Once a provider artifact is durable, the provider round has already
			// completed. Reissuing the request after a join/storage failure would
			// generate a fresh provider challenge and turn recovery into a false
			// duplicate-evidence rejection. Recover the existing round instead.
			results, listErr := m.store.ListProbeResults(op.ID)
			if listErr != nil {
				recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: list recovered evidence %q: %w", op.ID, listErr))
				continue
			}
			hasProviderEvidence := false
			providerEvidenceUsable := false
			challengePersistFailed := false
			ackValidationPending := false
			var providerEvidence providerResult
			for _, result := range results {
				if result.Kind != "provider" {
					continue
				}
				hasProviderEvidence = true
				decoded, decodeErr := decodeProviderResultJSON([]byte(result.PayloadHex))
				arm, armErr := probeArmFromOperation(op)
				if armErr != nil {
					// A malformed persisted ARM is controller state corruption,
					// not proof that the provider's accepted evidence is false.
					// Leave the operation live for repair or expiry, but surface the
					// recovery failure so an operator/supervisor can act on it.
					recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: recover operation %q ARM: %w", op.ID, armErr))
					continue
				}
				providerPub, keyErr := providerPublicKeyFromOperation(op)
				if keyErr != nil {
					recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: recover operation %q provider key: %w", op.ID, keyErr))
					continue
				}
				wan1, evidenceErr := validateAcceptedProviderEvidence(decoded, op, arm, providerPub)
				if decodeErr != nil || evidenceErr != nil {
					// A durable provider row is a completed provider round. If
					// its accepted result is malformed or incomplete, do not
					// suppress recovery and wait for expiry: the authenticated
					// provider evidence is permanently unusable.
					if terminalErr := m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeRejected); terminalErr != nil {
						recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: reject malformed recovered provider evidence %q: %w", op.ID, terminalErr))
					}
					break
				}
				if nodeKeyOK {
					if err := validateProviderACK1(decoded.ACK1Frame, arm, wan1, nodePub); err != nil {
						if terminalErr := m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeRejected); terminalErr != nil {
							recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: reject malformed recovered ACK1 %q: %w", op.ID, terminalErr))
						}
						break
					}
				} else {
					ackValidationPending = true
				}
				providerEvidence = decoded
				providerEvidenceUsable = true
				if challengeErr := m.store.SetProbeOperationChallenge(op.ID, decoded.ChallengeHash); challengeErr != nil {
					if errors.Is(challengeErr, store.ErrProbeJoinIncomplete) || errors.Is(challengeErr, store.ErrProbeChallengeConflict) {
						if terminalErr := m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeRejected); terminalErr != nil {
							recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: reject recovered challenge conflict %q: %w", op.ID, terminalErr))
						}
					} else {
						// A transient challenge write failure leaves the provider
						// round retryable. Do not call tryJoin with an unproven
						// challenge state.
						current, getErr := m.store.GetProbeOperation(op.ID)
						if getErr != nil || current.ChallengeHash == "" {
							challengePersistFailed = true
						}
					}
				}
				break
			}
			if hasProviderEvidence {
				if !providerEvidenceUsable || challengePersistFailed {
					continue
				}
				// The provider artifact may have been committed before a
				// transient WAN1/ACK1 artifact write failed. Reconcile the
				// exact provider response before attempting the join. These
				// bytes are copied from the authenticated provider result; the
				// store performs the node-key-dependent checks at join time.
				artifactPersistFailed := false
				artifactRejected := false
				for _, artifact := range []struct {
					kind, payload string
				}{
					{kind: "wan1", payload: providerEvidence.WAN1Frame},
					{kind: "ack1", payload: providerEvidence.ACK1Frame},
				} {
					if err := m.recordProviderArtifact(op.ID, artifact.kind, artifact.payload); err != nil {
						if errors.Is(err, store.ErrProbeDuplicateEvidence) {
							if terminalErr := m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeRejected); terminalErr != nil {
								recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: reject conflicting recovered artifact %q: %w", op.ID, terminalErr))
							}
							artifactRejected = true
						} else {
							artifactPersistFailed = true
						}
						break
					}
				}
				if artifactPersistFailed || artifactRejected {
					continue
				}
				if ackValidationPending {
					// Provider evidence, challenge, and exact artifact bytes are
					// durable, but ACK1 cannot be authenticated until reconnect.
					continue
				}
				if err := m.tryJoin(op); err != nil {
					recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: recover join %q: %w", op.ID, err))
				}
				continue
			}
			if err := m.store.RequeueProbeOperationForRecovery(op.ID); err != nil {
				recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: requeue recovered operation %q: %w", op.ID, err))
				continue
			}
			op.Status = "ARMED"
			if !nodeKeyOK {
				// Provider recovery is durable, but a new provider request needs
				// the authenticated live node session. Leave ARMED for reconnect.
				continue
			}
		}
		if !nodeKeyOK {
			continue
		}
		provider, err := m.store.GetProbeProvider(op.ProviderID)
		if err != nil {
			continue
		}
		if !provider.IndependentVantage {
			if err := m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeNoIndependentVantage); err != nil {
				recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: terminalize non-independent recovered operation %q: %w", op.ID, err))
			}
			continue
		}
		if err := m.startProvider(op, op.NodeID, nodePub); err != nil {
			recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: start recovered provider round %q: %w", op.ID, err))
		}
	}
	return errors.Join(recoveryErrs...)
}

// listRecoveryOperations returns the next fair live page and advances a
// manager-owned keyset cursor. Recovery passes are bounded, but repeated passes
// rotate through the live set instead of pinning the oldest offline row.
func (m *Manager) listRecoveryOperations(nowUnix int64) ([]store.ProbeOperation, error) {
	m.recoveryMu.Lock()
	defer m.recoveryMu.Unlock()
	ops, err := m.store.ListProbeOperationsByStatusLimitAtAfter(
		m.maxActive,
		nowUnix,
		m.recoveryAfter,
		m.recoveryAfterID,
		"ARMED",
		"IN_FLIGHT",
	)
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		m.recoveryAfter, m.recoveryAfterID = 0, ""
		return nil, nil
	}
	last := ops[len(ops)-1]
	m.recoveryAfter, m.recoveryAfterID = last.ExpiresAt, last.ID
	if len(ops) < m.maxActive {
		m.recoveryAfter, m.recoveryAfterID = 0, ""
	}
	return ops, nil
}

// recoverTerminalOutcomes repairs at most one caller-budgeted page per sweep.
// The cursor is manager-owned and serialized so concurrent reconnect/sweeper
// calls cannot turn a bounded page into duplicate full-history walks.
func (m *Manager) recoverTerminalOutcomes() error {
	m.terminalMu.Lock()
	defer m.terminalMu.Unlock()
	ops, err := m.store.ListUndeliveredTerminalProbeOperationsPage(m.cleanupBatch, m.terminalAfter, m.terminalAfterID)
	if err != nil {
		return fmt.Errorf("probe: list terminal outcomes for recovery: %w", err)
	}
	if len(ops) == 0 {
		m.terminalAfter, m.terminalAfterID = 0, ""
		return nil
	}
	var recoveryErrs []error
	for _, op := range ops {
		acked, err := m.store.ProbeOutcomeAcknowledged(op.ID)
		if err != nil {
			recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: inspect terminal outcome acknowledgement %q: %w", op.ID, err))
			// Advance over this row for this bounded page. A broken row must not
			// strand independent later rows; the cursor will wrap and retry it.
			m.terminalAfter, m.terminalAfterID = op.CreatedAt, op.ID
			continue
		}
		if !acked {
			// Terminal status and activation delivery are separate durable
			// boundaries. Keep the row RECEIVED/undelivered when enqueue fails,
			// but continue through the page so independent rows make progress.
			if err := m.enqueueActivationOutcome(op.ID, protocol.ProbeOutcome(op.Status)); err != nil {
				recoveryErrs = append(recoveryErrs, fmt.Errorf("probe: enqueue recovered terminal outcome %q: %w", op.ID, err))
			}
		}
		m.terminalAfter, m.terminalAfterID = op.CreatedAt, op.ID
	}
	if len(ops) < m.cleanupBatch {
		m.terminalAfter, m.terminalAfterID = 0, ""
	}
	return errors.Join(recoveryErrs...)
}

// recordBackgroundError retains asynchronous lifecycle failures in a bounded
// FIFO. Background work continues so recovery can retry the failed durable
// boundary, while a burst of independent failures cannot overwrite the only
// diagnostic that a supervisor has not read yet.
func (m *Manager) recordBackgroundError(err error) {
	if err == nil {
		return
	}
	m.backgroundErrMu.Lock()
	defer m.backgroundErrMu.Unlock()
	if len(m.backgroundErrs) >= maxBackgroundErrors {
		copy(m.backgroundErrs, m.backgroundErrs[1:])
		m.backgroundErrs[len(m.backgroundErrs)-1] = err
		return
	}
	m.backgroundErrs = append(m.backgroundErrs, err)
}

// BackgroundError returns and clears the oldest asynchronous lifecycle error.
// It is intended for supervisors and tests; nil means no error has been
// observed since the previous read. Each call removes only one error, so a
// supervisor cannot accidentally clear failures that arrived concurrently.
func (m *Manager) BackgroundError() error {
	m.backgroundErrMu.Lock()
	defer m.backgroundErrMu.Unlock()
	if len(m.backgroundErrs) == 0 {
		return nil
	}
	err := m.backgroundErrs[0]
	m.backgroundErrs[0] = nil
	m.backgroundErrs = m.backgroundErrs[1:]
	return err
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
	// WAN evidence owns only its three activation axes. Arm therefore requires
	// an Agent-observed runtime mirror for this exact activation; it must never
	// fabricate control/listener/mapping/target/data-plane truth.
	runtime, err := m.store.GetForwardRuntimeStatus(forwardID)
	if errors.Is(err, store.ErrNotFound) {
		return store.ProbeOperation{}, fmt.Errorf("probe: current runtime mirror: %w", err)
	}
	if err != nil {
		return store.ProbeOperation{}, fmt.Errorf("probe: read runtime mirror: %w", err)
	}
	if runtime.ActivationID != activationID {
		return store.ProbeOperation{}, fmt.Errorf("%w: runtime mirror activation is stale", store.ErrCASConflict)
	}
	if !runtime.GenerationBound || runtime.Generation != forward.Revision {
		return store.ProbeOperation{}, fmt.Errorf("%w: runtime mirror generation is stale", store.ErrCASConflict)
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
		ID:                      hex.EncodeToString(probeID[:]),
		NodeID:                  nodeID,
		ForwardID:               forwardID,
		ActivationID:            activationID,
		ExpectedForwardRevision: forward.Revision,
		ProviderID:              provider.ID,
		Status:                  "PENDING",
		Endpoint:                endpoint,
		ArmHex:                  hex.EncodeToString(arm.Canonical()),
		TTLMS:                   arm.TTLMS,
		ExpiryOpaque:            hex.EncodeToString(opaque[:]),
		ExpiresAt:               m.clock().Add(DefaultTTL).Unix(),
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

var errProbeChallengeNotEstablished = errors.New("probe: operation challenge is not established")

// permanentProbeReceiptError marks authenticated receipt input that cannot
// become valid by retrying (malformed framing, invalid correlation, or an
// unknown operation). The transport uses this marker to terminalize the inbox
// row while leaving ordinary store/sink failures retryable.
type permanentProbeReceiptError struct {
	err error
}

func (e *permanentProbeReceiptError) Error() string               { return e.err.Error() }
func (e *permanentProbeReceiptError) Unwrap() error               { return e.err }
func (e *permanentProbeReceiptError) PermanentProbeReceipt() bool { return true }

func permanentProbeReceipt(err error) error {
	if err == nil {
		return nil
	}
	return &permanentProbeReceiptError{err: err}
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

// staleActivationStatusError marks an authenticated status that was validly
// delivered but no longer belongs to the current forward activation. The hub
// must consume this as a harmless stale update, not tear down the session.
type staleActivationStatusError struct {
	err error
}

func (e *staleActivationStatusError) Error() string               { return e.err.Error() }
func (e *staleActivationStatusError) Unwrap() error               { return e.err }
func (e *staleActivationStatusError) StaleActivationStatus() bool { return true }

func staleActivationStatus(err error) error {
	if err == nil {
		return nil
	}
	return &staleActivationStatusError{err: err}
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
	if forward.NodeID != nodeID {
		return fmt.Errorf("probe: activation status node mismatch")
	}
	if forward.CurrentActivationID != v.Activation ||
		v.Generation == 0 || v.Generation != forward.Revision {
		return staleActivationStatus(store.ErrCASConflict)
	}
	stateJSON, err := json.Marshal(v.Snapshot)
	if err != nil {
		return err
	}
	if err := m.store.SetForwardRuntimeStatus(v.ForwardID, v.Activation, v.Generation, string(stateJSON)); err != nil {
		if errors.Is(err, store.ErrCASConflict) {
			return staleActivationStatus(err)
		}
		return err
	}
	return nil
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
	// Search the current live admission set first so delayed expiry rows cannot
	// consume the bound and hide a current RDY1. If no live row matches, include
	// bounded expired history so an RDY1 at the deadline can still be converted
	// to TIMEOUT before the sweeper runs.
	nowUnix := m.clock().Unix()
	op, err := m.store.ProbeOperationByArmDigestForNodeWithLimit(
		digest,
		nodeID,
		nowUnix,
		m.maxActive,
	)
	if errors.Is(err, store.ErrNotFound) {
		op, err = m.store.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(
			digest,
			nodeID,
			m.maxActive,
		)
	}
	if err != nil {
		return err
	}
	if nowUnix >= op.ExpiresAt {
		return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
	}
	// ARM1/RDY1 delivery is asynchronous. Re-read the forward after digest
	// correlation so a revision or activation change that committed after Arm
	// cannot admit provider work for stale controller intent.
	if err := m.validateCurrentForwardForProbe(op, nodeID); err != nil {
		if errors.Is(err, store.ErrCASConflict) || errors.Is(err, store.ErrForwardNotFound) {
			return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeRejected)
		}
		return err
	}
	switch op.Status {
	case "PENDING":
		if err := m.store.SetProbeOperationStatusCAS(op.ID, "PENDING", "ARMED"); err != nil {
			if errors.Is(err, store.ErrProbeTerminal) {
				return nil
			}
			return err
		}
		op.Status = "ARMED"
	case "ARMED":
		// The first provider round may have already ended after admitting this
		// operation. A duplicate RDY1 must not start a second independent
		// challenge round; the recovery loop owns retrying durable ARMED rows.
		return nil
	case "IN_FLIGHT":
		// The provider round is already owned by this operation. Do not launch a
		// second request on a duplicate RDY1; recovery or the active goroutine
		// owns the existing round.
		return nil
	default:
		// The bounded lookup excludes terminal rows, but a terminal winner may
		// race the lookup. A late RDY1 cannot resurrect it.
		return nil
	}
	provider, err := m.store.GetProbeProvider(op.ProviderID)
	if err != nil {
		if terminalErr := m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeProbeInfraUnavailable); terminalErr != nil {
			return errors.Join(err, fmt.Errorf("probe: terminalize missing provider %q: %w", op.ID, terminalErr))
		}
		return err
	}
	if !provider.IndependentVantage {
		return m.setTerminalOutcome(op.ID, "ARMED", protocol.OutcomeNoIndependentVantage)
	}
	// Request the provider asynchronously (bounded concurrency). startProvider
	// is itself idempotent for an operation already active in this Manager.
	if err := m.startProvider(op, nodeID, nodePub); err != nil {
		// Capacity pressure and manager lifecycle state are retryable admission
		// conditions. The durable ARMED row remains available to recovery; only
		// provider execution failures may produce a terminal infrastructure result.
		return err
	}
	return nil
}

func (m *Manager) validateCurrentForwardForProbe(op store.ProbeOperation, nodeID string) error {
	if op.ExpectedForwardRevision == 0 {
		return fmt.Errorf("%w: probe operation has no expected forward revision", store.ErrCASConflict)
	}
	forward, err := m.store.GetForward(op.ForwardID)
	if err != nil {
		return err
	}
	if forward.NodeID != nodeID || forward.NodeID != op.NodeID ||
		forward.CurrentActivationID != op.ActivationID ||
		forward.Revision != op.ExpectedForwardRevision {
		return store.ErrCASConflict
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
		return permanentProbeReceipt(fmt.Errorf("probe: probe_ingress_receipt rejected: %w", err))
	}
	// Search the currently live admission set first. Expired operation history is
	// retained for timeout terminalization, but it must not consume the active
	// correlation budget and hide a still-live receipt target.
	op, err := m.store.ProbeOperationByArmDigestForNodeWithLimit(
		receipt.ArmDigest,
		nodeID,
		m.clock().Unix(),
		m.maxActive,
	)
	if errors.Is(err, store.ErrNotFound) {
		op, err = m.store.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(
			receipt.ArmDigest,
			nodeID,
			m.maxActive,
		)
	}
	if errors.Is(err, store.ErrNotFound) {
		// A concurrent provider/receipt join may have already published the
		// operation while this exact receipt delivery was still in flight. Keep
		// terminal history out of ordinary correlation, but recognize a bounded
		// OPEN_FROM_VANTAGE replay within the wire receipt window below.
		op, err = m.store.ProbeOperationByArmDigestForNodeOpenWithinReplayWithLimit(
			receipt.ArmDigest,
			nodeID,
			m.clock().Add(-protocol.ProbeReplayWindow).Unix(),
			m.maxActive,
		)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return permanentProbeReceipt(fmt.Errorf("probe: probe_ingress_receipt has unknown arm digest: %w", err))
		}
		if errors.Is(err, store.ErrProbeCorrupt) {
			// Persisted ARM corruption is controller recovery state, not proof that
			// the authenticated RCT1 is invalid. Keep the receipt retryable so an
			// operator repair or a later bounded lookup can converge without losing
			// the exact durable receipt bytes.
			return fmt.Errorf("probe: probe_ingress_receipt correlation state requires repair: %w", err)
		}
		return err
	}
	// Correlation is checked before evidence admission. A node-authenticated
	// but mismatched provider receipt is a permanent rejection of this frame,
	// not a reason to poison the live operation; a later exact receipt remains
	// eligible to complete the join.
	armBytes, err := hex.DecodeString(op.ArmHex)
	if err != nil {
		return fmt.Errorf("probe: stored arm is malformed: %w", err)
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return fmt.Errorf("probe: stored arm is invalid: %w", err)
	}
	if receipt.ProviderID != arm.ProviderID {
		return permanentProbeReceipt(errors.New("probe: receipt provider does not match arm"))
	}
	// Expiry is handled before challenge admission. A live operation whose
	// provider response never durably established a challenge must still be
	// terminalized as TIMEOUT once its deadline passes; it must not remain live
	// merely because the RCT1 arrived during the provider-result race window.
	if op.Status == string(protocol.OutcomeOpenFromVantage) {
		// A replay that finds a joined terminal operation is idempotent only
		// after the authenticated receipt matches the durable RCT1 artifact.
		// Check this before the deadline branch: the protocol replay window
		// permits an exact receipt to arrive after the original TTL, while a
		// conflicting or missing artifact must remain fail-closed.
		results, listErr := m.store.ListProbeResults(op.ID)
		if listErr != nil {
			return listErr
		}
		want := hex.EncodeToString(payload)
		for _, result := range results {
			if result.Kind == "rct1" {
				if result.PayloadHex == want {
					return nil
				}
				return permanentProbeReceipt(errors.New("probe: conflicting receipt evidence for joined operation"))
			}
		}
		return fmt.Errorf("probe: joined operation is missing durable RCT1 evidence")
	}
	// Expiry is handled before challenge admission. A live operation whose
	// provider response never durably established a challenge must still be
	// terminalized as TIMEOUT once its deadline passes; it must not remain live
	// merely because the RCT1 arrived during the provider-result race window.
	if !m.clock().Before(time.Unix(op.ExpiresAt, 0)) {
		if op.Status == "ARMED" || op.Status == "IN_FLIGHT" || op.Status == "PENDING" {
			return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
		}
		return nil
	}
	if op.ChallengeHash == "" {
		// The provider challenge is the join nonce. Until it is durably known,
		// an authenticated RCT1 cannot be admitted because its challenge cannot
		// yet be correlated to this operation. AgentHub keeps the inbox RECEIVED
		// for this retryable race; the Agent resends after the provider result is
		// durable.
		return errProbeChallengeNotEstablished
	}
	challenge, decodeErr := hex.DecodeString(op.ChallengeHash)
	if decodeErr != nil || len(challenge) != protocol.ProbeDigestLen {
		if decodeErr != nil {
			return fmt.Errorf("probe: stored challenge hash is corrupt: %w", decodeErr)
		}
		return errors.New("probe: stored challenge hash is corrupt")
	}
	if !bytes.Equal(challenge, receipt.ChallengeHash[:]) {
		return permanentProbeReceipt(errors.New("probe: receipt challenge does not match operation"))
	}
	if op.Status != "ARMED" && op.Status != "IN_FLIGHT" {
		return nil // late receipts cannot resurrect a terminal operation
	}
	receiptHex := hex.EncodeToString(payload)
	if m.beforeRecordProbeResult != nil {
		m.beforeRecordProbeResult(op.ID, "rct1", receiptHex)
	}
	if err := m.store.RecordProbeResult(op.ID, "rct1", receiptHex); err != nil {
		if errors.Is(err, store.ErrProbeExpired) {
			return m.setTerminalOutcome(op.ID, op.Status, protocol.OutcomeTimeout)
		}
		if errors.Is(err, store.ErrProbeDuplicateEvidence) {
			if terminalErr := m.failOperation(op.ID, string(protocol.OutcomeRejected)); terminalErr != nil {
				// Do not permanently consume the Agent's receipt until the
				// controller has durably decided the negative operation outcome.
				return fmt.Errorf("probe: reject conflicting receipt: %w", terminalErr)
			}
			return permanentProbeReceipt(fmt.Errorf("probe: conflicting receipt evidence: %w", err))
		}
		if errors.Is(err, store.ErrProbeTerminal) {
			current, getErr := m.store.GetProbeOperation(op.ID)
			if getErr != nil {
				// The terminal race is established, but the winning row may
				// be temporarily unavailable during recovery/GC. Keep the
				// receipt retryable until its durable disposition can be read.
				return getErr
			}
			if current.Status == string(protocol.OutcomeOpenFromVantage) {
				results, listErr := m.store.ListProbeResults(op.ID)
				if listErr != nil {
					return listErr
				}
				want := hex.EncodeToString(payload)
				for _, result := range results {
					if result.Kind == "rct1" && result.PayloadHex == want {
						return nil
					}
				}
				// A joined operation without the exact durable receipt is
				// an incomplete persistence state, not proof that this
				// authenticated receipt is malformed. Leave it retryable.
				return err
			}
			// Any other terminal winner has durably decided that this
			// authenticated RCT1 cannot be admitted. Mark the receipt
			// permanently rejected so AgentHub can consume the inbox row
			// and emit the semantic acknowledgement; never reopen the op.
			return permanentProbeReceipt(fmt.Errorf("probe: receipt arrived after terminal outcome %q: %w", current.Status, err))
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

// validateAcceptedProviderEvidence validates the provider-signed result and
// provider-owned WAN1 evidence. It deliberately does not validate ACK1: ACK1
// is signed by the node session key, which may be temporarily unavailable
// during controller recovery.
func validateAcceptedProviderEvidence(res providerResult, op store.ProbeOperation, arm protocol.ProbeArm, providerPub ed25519.PublicKey) (protocol.ProviderFrame, error) {
	if res.Schema != providerResultSchema || !res.Accepted || res.ProbeID != op.ID {
		return protocol.ProviderFrame{}, errors.New("probe: provider result is not an accepted result for this operation")
	}
	challenge, err := hex.DecodeString(res.ChallengeHash)
	if err != nil || len(challenge) != protocol.ProbeDigestLen {
		return protocol.ProviderFrame{}, errors.New("probe: provider result has an invalid challenge hash")
	}
	if res.WAN1Frame == "" || res.ACK1Frame == "" {
		return protocol.ProviderFrame{}, errors.New("probe: provider result is missing WAN1 or ACK1 evidence")
	}
	wan1Bytes, err := hex.DecodeString(res.WAN1Frame)
	if err != nil {
		return protocol.ProviderFrame{}, fmt.Errorf("probe: provider WAN1 evidence is not hexadecimal: %w", err)
	}
	// ACK1 is node-authenticated. Keep its exact nonempty payload for durable
	// recovery, but defer all decoding and binding checks until the node session
	// key is available.
	if len(providerPub) != ed25519.PublicKeySize ||
		!bytes.Equal(providerPub, arm.ProviderPublicKey[:]) ||
		!res.verify(providerPub) {
		return protocol.ProviderFrame{}, errors.New("probe: provider result signature is invalid or not bound to ARM1")
	}
	if res.TimestampUnix < op.CreatedAt-5*60 || res.TimestampUnix > op.ExpiresAt+5*60 {
		return protocol.ProviderFrame{}, errors.New("probe: provider result timestamp is outside operation window")
	}
	wan1, err := protocol.ParseProviderFrame(wan1Bytes)
	if err != nil {
		return protocol.ProviderFrame{}, fmt.Errorf("probe: provider WAN1 evidence is malformed: %w", err)
	}
	if !ed25519.Verify(providerPub, wan1.SigningBytes(), wan1.Signature) {
		return protocol.ProviderFrame{}, errors.New("probe: provider WAN1 evidence signature is invalid")
	}
	frameChallenge := wan1.ChallengeHash()
	if wan1.ArmDigest != arm.Digest() ||
		wan1.ProbeID != arm.ProbeID ||
		wan1.ProviderID != arm.ProviderID ||
		wan1.Activation != arm.Activation ||
		wan1.Endpoint != arm.Endpoint ||
		wan1.ExpiryOpaque != arm.ExpiryOpaque ||
		!bytes.Equal(frameChallenge[:], challenge) {
		return protocol.ProviderFrame{}, errors.New("probe: provider WAN1 evidence is not bound to the operation")
	}
	return wan1, nil
}

// validateProviderACK1 validates the node-signed same-path acknowledgement
// after a live node session key is available.
func validateProviderACK1(ack1Hex string, arm protocol.ProbeArm, wan1 protocol.ProviderFrame, nodePub ed25519.PublicKey) error {
	if len(nodePub) != ed25519.PublicKeySize {
		return errors.New("probe: node public key is unavailable for ACK1 validation")
	}
	ack1Bytes, err := hex.DecodeString(ack1Hex)
	if err != nil {
		return fmt.Errorf("probe: provider ACK1 evidence is not hexadecimal: %w", err)
	}
	ack1, err := protocol.ParseProbeACK(ack1Bytes, nodePub)
	if err != nil {
		return fmt.Errorf("probe: provider ACK1 evidence is malformed: %w", err)
	}
	frameChallenge := wan1.ChallengeHash()
	if ack1.ArmDigest != arm.Digest() || ack1.ChallengeHash != frameChallenge {
		return errors.New("probe: provider ACK1 evidence is not bound to the operation")
	}
	return nil
}

func validateAcceptedProviderResult(res providerResult, op store.ProbeOperation, arm protocol.ProbeArm, providerPub, nodePub ed25519.PublicKey) error {
	wan1, err := validateAcceptedProviderEvidence(res, op, arm, providerPub)
	if err != nil {
		return err
	}
	return validateProviderACK1(res.ACK1Frame, arm, wan1, nodePub)
}

func probeArmFromOperation(op store.ProbeOperation) (protocol.ProbeArm, error) {
	armBytes, err := hex.DecodeString(op.ArmHex)
	if err != nil {
		return protocol.ProbeArm{}, fmt.Errorf("probe: stored ARM is malformed: %w", err)
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return protocol.ProbeArm{}, fmt.Errorf("probe: stored ARM is invalid: %w", err)
	}
	return arm, nil
}

func providerPublicKeyFromOperation(op store.ProbeOperation) (ed25519.PublicKey, error) {
	arm, err := probeArmFromOperation(op)
	if err != nil {
		return nil, err
	}
	pub := make([]byte, ed25519.PublicKeySize)
	copy(pub, arm.ProviderPublicKey[:])
	return ed25519.PublicKey(pub), nil
}

// requestProvider sends the controller-signed provider request and records
// the result artifacts; then tries the join.
func (m *Manager) requestProvider(requestCtx context.Context, op store.ProbeOperation, nodeID string, nodePub ed25519.PublicKey) error {
	provider, err := m.store.GetProbeProvider(op.ProviderID)
	if err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	if !provider.IndependentVantage {
		return m.failOperation(op.ID, string(protocol.OutcomeNoIndependentVantage))
	}
	deadline := time.Unix(op.ExpiresAt, 0)
	if !m.clock().Before(deadline) {
		return m.failOperation(op.ID, string(protocol.OutcomeTimeout))
	}
	ctx, cancel := context.WithDeadline(requestCtx, deadline)
	defer cancel()
	if err := m.store.SetProbeOperationStatusCAS(op.ID, "ARMED", "IN_FLIGHT"); err != nil {
		return err
	}
	armBytes, err := hex.DecodeString(op.ArmHex)
	if err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeRejected)))
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
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeRejected)))
	}
	sig, err := m.keyring.Sign(canonical)
	if err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	req.Signature = hex.EncodeToString(sig)

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(provider.Endpoint, "/")+"/probe/v1/request", bytes.NewReader(body))
	if err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || !m.clock().Before(deadline) {
			return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeTimeout)))
		}
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(requestCtx.Err(), context.Canceled) {
			// Manager shutdown or a parent lifecycle cancellation is not provider
			// evidence. Leave the IN_FLIGHT row for restart recovery.
			return err
		}
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
	}
	const maxProviderResponseBytes = int64(protocol.MaxPayloadBytes)
	if resp.ContentLength > maxProviderResponseBytes {
		return m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponseBytes+1))
	if err != nil || int64(len(bodyBytes)) > maxProviderResponseBytes {
		if err == nil {
			err = errors.New("provider response exceeds maximum size")
		}
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	res, err := decodeProviderResultJSON(bodyBytes)
	if err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable)))
	}
	if res.ProbeID != op.ID {
		return m.failOperation(op.ID, string(protocol.OutcomeRejected))
	}
	const resultClockSkewSeconds int64 = 5 * 60
	if res.TimestampUnix < op.CreatedAt-resultClockSkewSeconds || res.TimestampUnix > op.ExpiresAt+resultClockSkewSeconds {
		return m.failOperation(op.ID, string(protocol.OutcomeTimeout))
	}
	providerPub, err := hex.DecodeString(provider.PublicKey)
	if err != nil || len(providerPub) != ed25519.PublicKeySize {
		return m.failOperation(op.ID, string(protocol.OutcomeProbeInfraUnavailable))
	}
	if !res.verify(providerPub) {
		return m.failOperation(op.ID, string(protocol.OutcomeRejected))
	}
	if !res.Accepted {
		if status, terminal := providerFailureOutcome(res.Reason); terminal {
			return m.failOperation(op.ID, status)
		}
		// pending/busy are transient admission results. Keep the operation in
		// IN_FLIGHT so recovery requeues it instead of manufacturing REJECTED.
		return nil
	}
	if err := validateAcceptedProviderResult(res, op, arm, ed25519.PublicKey(providerPub), nodePub); err != nil {
		return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeRejected)))
	}
	if err := m.recordProviderArtifact(op.ID, "provider", mustJSON(res)); err != nil {
		if errors.Is(err, store.ErrProbeDuplicateEvidence) {
			return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeRejected)))
		}
		// Storage contention, commit failure, and other internal errors
		// leave IN_FLIGHT for recovery; they are not provider evidence
		// rejection.
		return err
	}
	if res.WAN1Frame != "" {
		if err := m.recordProviderArtifact(op.ID, "wan1", res.WAN1Frame); err != nil {
			if errors.Is(err, store.ErrProbeDuplicateEvidence) {
				return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeRejected)))
			}
			return err
		}
	}
	if res.ACK1Frame != "" {
		if err := m.recordProviderArtifact(op.ID, "ack1", res.ACK1Frame); err != nil {
			if errors.Is(err, store.ErrProbeDuplicateEvidence) {
				return errors.Join(err, m.failOperation(op.ID, string(protocol.OutcomeRejected)))
			}
			return err
		}
	}
	if err := m.store.SetProbeOperationChallenge(op.ID, res.ChallengeHash); err != nil {
		// Challenge persistence is a prerequisite for admission. A transient
		// store failure leaves the provider round IN_FLIGHT for recovery; it
		// must not become a terminal infrastructure or rejection outcome.
		return err
	}
	if !res.Accepted {
		return m.failOperation(op.ID, string(protocol.OutcomeRejected))
	}
	if res.ChallengeHash == "" || res.WAN1Frame == "" || res.ACK1Frame == "" {
		return m.failOperation(op.ID, string(protocol.OutcomeRejected))
	}
	if err := m.tryJoin(op); err != nil {
		if errors.Is(err, store.ErrProbeExpired) {
			if terminalErr := m.failOperation(op.ID, string(protocol.OutcomeTimeout)); terminalErr != nil {
				return errors.Join(err, terminalErr)
			}
		} else if errors.Is(err, store.ErrCASConflict) {
			// A forward/activation fence conflict is a proven stale join and may
			// be terminalized. Other errors (SQLite contention, unavailable
			// storage, or a post-publication queue failure) are retryable and must
			// not be converted into a false REJECTED probe outcome.
			if terminalErr := m.failOperation(op.ID, string(protocol.OutcomeRejected)); terminalErr != nil {
				return errors.Join(err, terminalErr)
			}
		}
		return err
	}
	return nil
}

// recordProviderArtifact delegates exact replay/conflict handling to the
// store. RecordProbeResult returns nil only for byte-identical evidence; a
// conflicting artifact remains ErrProbeDuplicateEvidence and must fail closed.
func (m *Manager) recordProviderArtifact(operationID, kind, payload string) error {
	return m.store.RecordProbeResult(operationID, kind, payload)
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
		if err := m.failOperation(op.ID, string(protocol.OutcomeTimeout)); err != nil {
			return err
		}
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
		if terminalErr := m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected); terminalErr != nil {
			return errors.Join(cause, terminalErr)
		}
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
	if current.ChallengeHash == "" {
		// Provider evidence is durable, but the challenge write may still be
		// incomplete after a transient storage failure. This is retryable
		// controller state, not proof that the authenticated receipt is invalid.
		return errProbeChallengeNotEstablished
	}
	if !strings.EqualFold(current.ChallengeHash, providerRes.ChallengeHash) ||
		!strings.EqualFold(providerRes.ChallengeHash, frameChallengeHex) {
		return m.setTerminalOutcome(op.ID, current.Status, protocol.OutcomeRejected)
	}
	nodePub, ok := m.nodeKey(current.NodeID)
	if !ok {
		// The provider round and receipt may already be durable. A temporary
		// node-session loss is retryable; do not terminalize valid evidence.
		return errors.New("probe: node session lost before join")
	}
	ack1, err := hex.DecodeString(ack1Hex)
	if err != nil {
		return reject(err)
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
		switch {
		case errors.Is(err, store.ErrProbeExpired):
			if terminalErr := m.failOperation(op.ID, string(protocol.OutcomeTimeout)); terminalErr != nil {
				return errors.Join(err, terminalErr)
			}
		case errors.Is(err, store.ErrCASConflict), errors.Is(err, store.ErrProbeJoinIncomplete):
			// A stale activation fence or proven malformed/conflicting evidence is
			// a permanent join failure. Storage contention, a concurrent terminal
			// winner, and other internal errors remain retryable and must not be
			// converted into a false REJECTED outcome.
			if terminalErr := m.failOperation(op.ID, string(protocol.OutcomeRejected)); terminalErr != nil {
				return errors.Join(err, terminalErr)
			}
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
func (m *Manager) failOperation(id, status string) error {
	op, err := m.store.GetProbeOperation(id)
	if err != nil {
		m.recordBackgroundError(fmt.Errorf("probe: read operation %q for terminalization: %w", id, err))
		return err
	}
	if op.Status == status || op.Status == string(protocol.OutcomeOpenFromVantage) ||
		op.Status == string(protocol.OutcomeRejected) || op.Status == string(protocol.OutcomeDropped) ||
		op.Status == string(protocol.OutcomeTimeout) || op.Status == string(protocol.OutcomeNoIndependentVantage) ||
		op.Status == string(protocol.OutcomeProbeInfraUnavailable) {
		return nil
	}
	if err := m.setTerminalOutcome(id, op.Status, protocol.ProbeOutcome(status)); err != nil {
		m.recordBackgroundError(fmt.Errorf("probe: terminalize operation %q as %s: %w", id, status, err))
		return err
	}
	return nil
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
