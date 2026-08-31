// Agent app composition (P10 Story 5).
//
// Composes the agent process from its P07/P08/P10 services: the localstate
// store, node identity key, enrollment, the control channel client, the
// reconciler with the P09 direct-v4 data plane, and the probe plane. The
// OnCommand hook routes controller commands: desired snapshots reconcile
// through the data plane, probe_arm goes through the durable probe manager.
// Startup failure rolls back readiness; Shutdown closes the control client,
// then the data plane, then the store, in that order.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT/internal/forward"
	"github.com/gxbrave/AntiNAT/internal/forward/tcp"
	udpforward "github.com/gxbrave/AntiNAT/internal/forward/udp"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// Config wires the agent app.
type Config struct {
	// StateDir is the agent localstate directory (bbolt + node key).
	StateDir string
	// Endpoint is the controller base URL (http:// or https://).
	Endpoint string
	// NodeID is the agent's node identity (store-form string).
	NodeID string
	// Token is the one-time enrollment token (hidden input). Empty when the
	// agent is already enrolled (restart path).
	Token string
	// ControllerPublicKey is the PINNED controller signing key (from the
	// deployment profile).
	ControllerPublicKey ed25519.PublicKey
	// Heartbeat is the control heartbeat interval (0 disables).
	Heartbeat time.Duration
	// Clock is the wall clock (deterministic tests).
	Clock func() time.Time
	// RouteTable overrides the direct-v4 source assessment (tests inject a
	// deterministic table; nil uses the live host table).
	RouteTable traversal.RouteTable
	// LivenessInterval controls route/interface capability polling. Zero uses
	// a conservative default.
	LivenessInterval time.Duration
}

// App is one composed agent process.
type App struct {
	cfg Config

	store *localstate.Store
	key   *security.NodeKey

	client     controlClient
	reconciler *reconcile.Reconciler
	probeMgr   *reconcile.ProbeManager
	dp         *dataPlane

	// activations tracks the orthogonal activation state machine per applied
	// forward (Story 3). The map is guarded by dp.mu.
	activations map[string]*reconcile.Activation
	// marker/latch are loaded once from the durable terminal boundary. The latch
	// is shared with the reconciler and all actor admission paths.
	marker localstate.MarkerState
	latch  *localstate.Latch
	// probeAdmissionMu serializes activation replacement with probe admission.
	// A probe arm must not observe one revision and transition another.
	probeAdmissionMu sync.Mutex

	ready atomic.Bool

	shutdownMu      sync.Mutex
	closeMu         sync.Mutex
	closed          bool
	shutdownStarted bool
	reconnectWG     sync.WaitGroup
	runCancel       context.CancelFunc
	lifecycleWG     sync.WaitGroup
}

// controlClient is the lifecycle surface the composed app needs from the
// transport. Keeping it narrow makes startup rollback testable without
// weakening the concrete control client used in production.
type controlClient interface {
	Connect(context.Context) error
	SendMessage(context.Context, string, []byte) error
	// Close ends only the current transport session. The client remains
	// reusable, so a transient post-connect recovery failure can force the
	// reconnect loop across a fresh session boundary without terminal shutdown.
	Close()
	Shutdown()
	Wait()
}

type contextShutdownClient interface {
	controlClient
	ShutdownContext(context.Context) error
}

// New opens the localstate store, loads or creates the node key, and
// enrolls when a token is provided. Any failure rolls back everything
// already opened.
func New(cfg Config) (*App, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("agent: state dir is required")
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("agent: endpoint is required")
	}
	if cfg.NodeID == "" {
		return nil, errors.New("agent: node id is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.LivenessInterval <= 0 {
		cfg.LivenessInterval = 5 * time.Second
	}
	if cfg.RouteTable == nil {
		cfg.RouteTable = traversal.HostRouteTable{}
	}
	// The terminal marker is an independent startup boundary. Read it before
	// opening bbolt or creating/loading a node key, and never attempt enrollment
	// from a terminal state.
	marker, err := localstate.LoadMarker(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("agent: load terminal marker: %w", err)
	}
	if marker != localstate.MarkerActive && cfg.Token != "" {
		return nil, fmt.Errorf("agent: enrollment token rejected with terminal marker %s", marker)
	}

	a := &App{cfg: cfg, marker: marker}

	st, err := localstate.Open(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("agent: open localstate: %w", err)
	}
	a.store = st
	rollback := func(cause error) (*App, error) {
		_ = st.Close()
		return nil, cause
	}

	// Enrollment (one-time token) or key load (restart).
	var key *security.NodeKey
	if cfg.Token != "" {
		key, err = control.Enroll(context.Background(), st, control.EnrollOptions{
			Endpoint:            cfg.Endpoint,
			NodeID:              cfg.NodeID,
			Token:               cfg.Token,
			ControllerPublicKey: cfg.ControllerPublicKey,
			KeyDir:              cfg.StateDir,
		})
		if err != nil {
			return rollback(fmt.Errorf("agent: enroll: %w", err))
		}
	} else {
		key, err = security.LoadOrCreateNodeKey(cfg.StateDir, 1)
		if err != nil {
			return rollback(fmt.Errorf("agent: node key: %w", err))
		}
	}
	a.key = key

	// Probe plane first: the data plane wraps its gate around listeners and
	// the reconciler's apply hook uses it. SendControl is wired lazily to
	// the control client once it exists.
	a.probeMgr = reconcile.NewProbeManager(reconcile.ProbeManagerOptions{
		Store:   st,
		NodeKey: key,
		Clock:   cfg.Clock,
		Marker:  marker,
		SendControl: func(ctx context.Context, messageType string, payload []byte) error {
			if a.client == nil {
				return errors.New("agent: control client not started")
			}
			return a.client.SendMessage(ctx, messageType, payload)
		},
		ReceiptRetryInterval: 500 * time.Millisecond,
	})

	a.dp = newDataPlane(dataPlaneConfig{
		Store:      st,
		ProbeMgr:   a.probeMgr,
		RouteTable: cfg.RouteTable,
		Clock:      cfg.Clock,
		OnApplied: func(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
			a.onForwardApplied(spec, applied)
		},
		OnDeleted: func(forwardID string) {
			a.onForwardDeleted(forwardID)
		},
		OnRunError: func(forwardID string, actor *forwardActor, err error) {
			a.onForwardRunError(forwardID, actor, err)
		},
		OnCleanupError: func(forwardID string, actor *forwardActor, err error) {
			a.onForwardCleanupError(forwardID, actor, err)
		},
	})
	a.activations = make(map[string]*reconcile.Activation)

	a.marker = marker
	a.latch = localstate.NewLatch()
	if marker != localstate.MarkerActive {
		a.latch.TryEngage()
	}
	a.reconciler = reconcile.NewWithRollback(st, a.latch, marker,
		a.dp.apply, a.dp.stop, a.dp.rollback, a.dp.capabilityCheck)

	client, err := control.NewClient(control.ClientOptions{
		Endpoint:            cfg.Endpoint,
		NodeID:              cfg.NodeID,
		Store:               st,
		Key:                 key,
		Heartbeat:           cfg.Heartbeat,
		OnCommand:           a.handleCommand,
		OnRecoveredDeletion: a.convergeRecoveredDeletions,
		OnReceipt: func(ctx context.Context, operationID string) error {
			return a.probeMgr.AcknowledgeReceipt(operationID)
		},
	})
	if err != nil {
		return rollback(fmt.Errorf("agent: control client: %w", err))
	}
	a.client = client
	return a, nil
}

// Start connects the control channel and marks the app ready once the
// session handshake completes. ctx bounds startup and the initial handshake;
// after a successful connection the app owns an independent runtime context
// that is canceled by Shutdown.
func (a *App) Start(ctx context.Context) error {
	a.shutdownMu.Lock()
	defer a.shutdownMu.Unlock()
	a.closeMu.Lock()
	if a.closed || a.shutdownStarted {
		a.closeMu.Unlock()
		return errors.New("agent: app is closed")
	}
	a.closeMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	startupCtx := ctx
	runCtx, runCancel := context.WithCancel(context.Background())
	a.closeMu.Lock()
	a.runCancel = runCancel
	a.closeMu.Unlock()
	// Recover durable activation/listener state before opening the control
	// session. Connect invokes the command handler synchronously, so accepting
	// frames before this barrier would race a stale activation/listener map.
	// A terminal marker is a one-way recovery boundary: do not restore stale
	// activation evidence or LKG listeners from disk.
	if a.marker == localstate.MarkerActive {
		if err := a.prepareActivationRecovery(); err != nil {
			runCancel()
			a.client.Shutdown()
			a.client.Wait()
			_ = a.dp.closeAll(context.Background())
			a.probeMgr.Close()
			_ = a.store.Close()
			return fmt.Errorf("agent: prepare activation recovery: %w", err)
		}
		if err := a.dp.recover(startupCtx); err != nil {
			runCancel()
			a.client.Shutdown()
			a.client.Wait()
			_ = a.dp.closeAll(context.Background())
			a.probeMgr.Close()
			_ = a.store.Close()
			return fmt.Errorf("agent: data plane recovery: %w", err)
		}
	}
	if err := a.client.Connect(startupCtx); err != nil {
		runCancel()
		a.client.Shutdown()
		a.client.Wait()
		_ = a.dp.closeAll(context.Background())
		a.probeMgr.Close()
		_ = a.store.Close()
		return fmt.Errorf("agent: control connect: %w", err)
	}
	a.probeMgr.Start(runCtx)
	a.dp.startCleanupDrain(runCtx)
	// A receipt may have been durably recorded immediately before a crash or
	// control disconnect. Retry it after the new session is established.
	if err := a.probeMgr.RetryPendingReceipts(runCtx); err != nil {
		runCancel()
		a.client.Shutdown()
		a.client.Wait()
		_ = a.dp.closeAll(context.Background())
		a.probeMgr.Close()
		_ = a.store.Close()
		return fmt.Errorf("agent: retry pending probe receipts: %w", err)
	}
	if a.marker == localstate.MarkerActive {
		a.replayActivationStatuses(runCtx)
		a.lifecycleWG.Add(1)
		go func() {
			defer a.lifecycleWG.Done()
			a.monitorLiveness(runCtx)
		}()
		a.reconnectWG.Add(1)
		go func() {
			defer a.reconnectWG.Done()
			a.reconnectControl(runCtx)
		}()
	}
	a.ready.Store(true)
	return nil
}

// prepareActivationRecovery rewrites persisted snapshots before any status
// replay or listener recovery. This ordering prevents a stale verified mirror
// from being published during the reconnect window.
func (a *App) listActivationSnapshots() ([]localstate.ActivationSnapshot, error) {
	if a.store == nil {
		return nil, nil
	}
	const pageSize = 256
	var all []localstate.ActivationSnapshot
	cursor := ""
	for {
		page, next, err := a.store.ListActivationSnapshotsPage(pageSize, cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if next == "" {
			return all, nil
		}
		cursor = next
	}
}

// readForwardDeleteFence reads the durable deletion facts that gate recovery
// and actor admission. The pending intent and final tombstone are both
// no-resurrection fences; callers must fail closed on a malformed fence.
func readForwardDeleteFence(st *localstate.Store, forwardID string) (pending, tombstoned bool, err error) {
	if st == nil {
		return false, false, nil
	}
	_, pending, _, tombstoned, err = st.ForwardDeleteFence(forwardID)
	return pending, tombstoned, err
}

func forwardDeleteFenceError(forwardID string, pending, tombstoned bool) error {
	if tombstoned {
		return fmt.Errorf("agent: forward %q is fenced by durable deletion tombstone: %w", forwardID, localstate.ErrTombstonedForward)
	}
	if pending {
		return fmt.Errorf("agent: forward %q is fenced by pending deletion cleanup: %w", forwardID, localstate.ErrForwardDeletePending)
	}
	return nil
}

func (a *App) prepareActivationRecovery() error {
	if a.store == nil {
		return nil
	}
	snapshots, err := a.listActivationSnapshots()
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		pending, tombstoned, err := readForwardDeleteFence(a.store, snapshot.ForwardID)
		if err != nil {
			return fmt.Errorf("activation %s delete fence: %w", snapshot.ForwardID, err)
		}
		if pending || tombstoned {
			// A pending or final deletion fence is authoritative over any
			// activation mirror left by a crash. Do not restore it for replay.
			continue
		}
		act := reconcile.NewActivation(snapshot.ForwardID, snapshot.Activation, snapshot.Generation)
		if err := act.Set(snapshot.States); err != nil {
			return fmt.Errorf("activation %s: %w", snapshot.ForwardID, err)
		}
		if err := act.RecoverAfterRestart(); err != nil {
			return fmt.Errorf("activation %s recovery: %w", snapshot.ForwardID, err)
		}
		state := act.Snapshot()
		if err := a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: snapshot.ForwardID, Activation: snapshot.Activation,
			Generation: snapshot.Generation, States: state,
		}); err != nil {
			return fmt.Errorf("activation %s save recovery: %w", snapshot.ForwardID, err)
		}
	}
	return nil
}

// replayActivationStatuses re-sends persisted evidence-loss mirrors after a
// reconnect. The status message is idempotent and the controller applies its
// activation CAS before replacing the runtime row.
func (a *App) replayActivationStatuses(ctx context.Context) {
	if a.store == nil || a.client == nil {
		return
	}
	snapshots, err := a.listActivationSnapshots()
	if err != nil {
		return
	}
	for _, snapshot := range snapshots {
		pending, tombstoned, err := readForwardDeleteFence(a.store, snapshot.ForwardID)
		if err != nil || pending || tombstoned {
			// Deletion fences suppress status replay even when a stale activation
			// mirror survived before the durable delete transaction completed.
			continue
		}
		if snapshot.States.PublicationState == "NONE" {
			continue
		}
		payload, err := json.Marshal(struct {
			ForwardID  string                    `json:"forward_id"`
			Activation string                    `json:"activation"`
			Generation uint64                    `json:"generation"`
			Snapshot   protocol.ActivationStates `json:"snapshot"`
		}{snapshot.ForwardID, snapshot.Activation, snapshot.Generation, snapshot.States})
		if err == nil {
			a.sendActivationStatus(ctx, payload)
		}
	}
}

// sendActivationStatus uses a bounded write context. If the transport is
// unavailable, the persisted snapshot is replayed on the next reconnect.
func (a *App) sendActivationStatus(ctx context.Context, payload []byte) {
	if a.client == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = a.client.SendMessage(statusCtx, "status", payload)
}

// reconnectControl waits for a transport session to finish and reuses the
// same Client for the next handshake. Durable receipts are retried after every
// successful reconnect; a failed retry remains in localstate for the next
// pass and keeps readiness conservative.
func (a *App) reconnectControl(ctx context.Context) {
	if a.marker != localstate.MarkerActive || a.client == nil {
		return
	}
	for {
		if a.marker != localstate.MarkerActive {
			return
		}
		a.client.Wait()
		a.ready.Store(false)
		// A reconnect is also an evidence boundary: the old independent proof
		// cannot be treated as current while the control session was absent.
		a.markActivationsUnverified(ctx)
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := a.client.Connect(ctx); err != nil {
			if strings.Contains(err.Error(), "client is closed") || ctx.Err() != nil {
				return
			}
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			continue
		}
		a.replayActivationStatuses(ctx)
		if err := a.probeMgr.RetryPendingReceipts(ctx); err != nil {
			a.ready.Store(false)
			// RetryPendingReceipts may fail after the handshake while the
			// transport is still healthy (for example, a transient send or
			// localstate error). Force a non-terminal reconnect boundary;
			// otherwise the next iteration can block forever in Wait while the
			// same connected session remains unable to make receipt progress.
			if bounded, ok := a.client.(interface{ CloseContext(context.Context) error }); ok {
				_ = bounded.CloseContext(ctx)
			} else {
				a.client.Close()
			}
			continue
		}
		a.ready.Store(true)
	}
}

// Ready reports whether the control session is established.
func (a *App) Ready() bool { return a.ready.Load() }

// monitorLiveness polls the route/interface capability seam. A loss first
// tears down listeners and unpublishes activation evidence; recovery then
// reopens the durable desired forwards from the current bind state.
func (a *App) monitorLiveness(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.LivenessInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.marker != localstate.MarkerActive {
				continue
			}
			_, capability, assessErr := traversal.Assess(a.cfg.RouteTable)
			fingerprint, fingerprintErr := traversal.Fingerprint(a.cfg.RouteTable)
			available := assessErr == nil && capability == traversal.CapabilityDirectV4Ready && fingerprintErr == nil
			if !available {
				if a.dp.markCapabilityLost(ctx) {
					a.markEvidenceLost(ctx)
				}
				continue
			}
			if a.dp.capabilityChanged(fingerprint) {
				if a.dp.markCapabilityLost(ctx) {
					a.markEvidenceLost(ctx)
				}
				continue
			}
			if a.dp.markCapabilityRestored(fingerprint) {
				if err := a.dp.recover(ctx); err != nil {
					// Keep the capability degraded so the next poll retries
					// recovery, without claiming a listener is active.
					a.dp.markCapabilityLost(ctx)
				}
			}
		}
	}
}

func (a *App) markActivationsUnverified(ctx context.Context) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	if a.dp == nil {
		return
	}
	a.dp.mu.Lock()
	activations := make([]*reconcile.Activation, 0, len(a.activations))
	for _, act := range a.activations {
		activations = append(activations, act)
	}
	a.dp.mu.Unlock()
	for _, act := range activations {
		if err := act.RecoverAfterRestart(); err != nil {
			continue
		}
		state := act.Snapshot()
		if a.store != nil {
			_ = a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
				ForwardID: act.ForwardID(), Activation: act.ActivationID(),
				Generation: act.Generation(), States: state,
			})
		}
		payload, err := json.Marshal(struct {
			ForwardID  string                    `json:"forward_id"`
			Activation string                    `json:"activation"`
			Generation uint64                    `json:"generation"`
			Snapshot   protocol.ActivationStates `json:"snapshot"`
		}{act.ForwardID(), act.ActivationID(), act.Generation(), state})
		if err == nil && a.client != nil {
			a.sendActivationStatus(ctx, payload)
		}
	}
}

func (a *App) markEvidenceLost(ctx context.Context) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	if a.dp == nil {
		return
	}
	a.dp.mu.Lock()
	activations := make([]*reconcile.Activation, 0, len(a.activations))
	for _, act := range a.activations {
		activations = append(activations, act)
	}
	a.dp.mu.Unlock()
	for _, act := range activations {
		if err := act.EvidenceLost(); err != nil {
			continue
		}
		state := act.Snapshot()
		if a.store != nil {
			_ = a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
				ForwardID: act.ForwardID(), Activation: act.ActivationID(),
				Generation: act.Generation(), States: state,
			})
		}
		payload, err := json.Marshal(struct {
			ForwardID  string                    `json:"forward_id"`
			Activation string                    `json:"activation"`
			Generation uint64                    `json:"generation"`
			Snapshot   protocol.ActivationStates `json:"snapshot"`
		}{act.ForwardID(), act.ActivationID(), act.Generation(), state})
		if err == nil && a.client != nil {
			a.sendActivationStatus(ctx, payload)
		}
	}
}

// handleCommand is the control client's OnCommand hook: durable commands
// from the controller. It returns the semantic result payload or an error
// that NACKs the operation.
func (a *App) handleCommand(ctx context.Context, op control.Operation) ([]byte, error) {
	if a.marker != localstate.MarkerActive && op.MessageType == "probe_arm" {
		return nil, reconcile.ErrProbeArmRejected
	}
	switch op.MessageType {
	case "desired":
		return a.applyDesired(ctx, op)
	case "probe_arm":
		return a.armProbe(ctx, op)
	case "forward_delete":
		return a.applyDesired(ctx, op)
	case "probe_outcome":
		return a.applyProbeOutcome(op)
	default:
		return nil, fmt.Errorf("agent: unexpected command type %q", op.MessageType)
	}
}

// applyProbeOutcome joins the controller's durably accepted probe outcome
// into the matching activation. Activation and generation are both fenced so
// a delayed outcome cannot publish an older revision.
func (a *App) applyProbeOutcome(op control.Operation) ([]byte, error) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	var v struct {
		ForwardID  string `json:"forward_id"`
		Activation string `json:"activation"`
		Generation uint64 `json:"generation"`
		Outcome    string `json:"outcome"`
	}
	if err := protocol.DecodeStrictJSONInto(op.Payload, &v); err != nil {
		return nil, fmt.Errorf("agent: probe outcome decode: %w", err)
	}
	if v.ForwardID == "" || v.Activation == "" || v.Generation == 0 || v.Outcome == "" {
		return nil, errors.New("agent: incomplete probe outcome")
	}
	outcome, err := protocol.ParseProbeOutcome(v.Outcome)
	if err != nil {
		return nil, err
	}
	act := a.activation(v.ForwardID)
	if act == nil {
		return nil, fmt.Errorf("agent: activation %s not found", v.ForwardID)
	}
	if act.ActivationID() != v.Activation {
		return nil, reconcile.ErrStaleEvent
	}
	if err := act.RecordProbeOutcome(outcome, v.Generation); err != nil {
		return nil, err
	}
	state := act.Snapshot()
	if a.store != nil {
		if err := a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: v.ForwardID, Activation: v.Activation,
			Generation: v.Generation, States: state,
		}); err != nil {
			return nil, fmt.Errorf("agent: save probe outcome: %w", err)
		}
	}
	return json.Marshal(struct {
		Status     string                    `json:"status"`
		ForwardID  string                    `json:"forward_id"`
		Activation string                    `json:"activation"`
		Snapshot   protocol.ActivationStates `json:"snapshot"`
	}{"applied", v.ForwardID, v.Activation, state})
}

// convergeRecoveredDeletions applies only the ABSENT subset of an exact
// payload redelivery for a command recovered from APPLYING. Replaying the full
// mixed snapshot would be unsafe because PRESENT side effects may already have
// run before the crash. The deletion subset is idempotent, fenced at receive
// time, commits tombstones before stop, and records its real D-keyed outcomes.
func (a *App) convergeRecoveredDeletions(ctx context.Context, op control.Operation) error {
	if op.MessageType != "desired" && op.MessageType != "forward_delete" {
		return nil
	}
	var desired protocol.DesiredState
	if err := protocol.DecodeStrictJSONInto(op.Payload, &desired); err != nil {
		return fmt.Errorf("agent: recovered deletion decode: %w", err)
	}
	if err := desired.Validate(); err != nil {
		return fmt.Errorf("agent: recovered deletion desired: %w", err)
	}
	absent := protocol.DesiredState{NodeID: desired.NodeID}
	for _, spec := range desired.Forwards {
		if spec.Presence == protocol.PresenceAbsent {
			absent.Forwards = append(absent.Forwards, spec)
		}
	}
	if len(absent.Forwards) == 0 {
		return nil
	}
	epoch, session, err := a.store.CurrentSession()
	if err != nil {
		return err
	}
	report, err := a.reconciler.ReconcileOnce(ctx, absent, epoch, session)
	if err != nil {
		return err
	}
	if report.Status != localstate.ApplyStatusFull {
		return fmt.Errorf("agent: recovered deletion did not converge: %s", report.Status)
	}
	return nil
}

// applyDesired reconciles a desired snapshot through the data plane and
// returns the durable apply report as the command result.
func (a *App) applyDesired(ctx context.Context, op control.Operation) ([]byte, error) {
	var d protocol.DesiredState
	if err := protocol.DecodeStrictJSONInto(op.Payload, &d); err != nil {
		return nil, fmt.Errorf("agent: desired decode: %w", err)
	}
	epoch, session, err := a.store.CurrentSession()
	if err != nil {
		return nil, err
	}
	report, err := a.reconciler.ReconcileOnce(ctx, d, epoch, session)
	if err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

// armProbe handles a probe_arm command through the durable probe manager
// and returns the RDY1 frame as the command result.
func (a *App) armProbe(ctx context.Context, op control.Operation) ([]byte, error) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	if a.marker != localstate.MarkerActive {
		return nil, reconcile.ErrProbeArmRejected
	}
	if a.store == nil || a.probeMgr == nil || a.dp == nil {
		return nil, reconcile.ErrProbeArmRejected
	}

	arm, err := protocol.ParseProbeArm(op.Payload)
	if err != nil {
		return nil, err
	}
	// Resolve the forward whose applied activation matches the arm. The
	// admission mutex also fences onForwardApplied so the activation pointer,
	// durable applied revision, and RDY1 cannot describe different revisions.
	states, err := a.store.ListAppliedStates()
	if err != nil {
		return nil, err
	}
	for _, s := range states {
		wantActivation := protocol.ActivationID(s.ForwardID, s.SpecRevision)
		if arm.Activation != wantActivation {
			continue
		}
		act := a.activation(s.ForwardID)
		if act == nil {
			return nil, reconcile.ErrProbeArmRejected
		}
		forwardID, currentActivation, generation, snapshot := act.IdentitySnapshot()
		if forwardID != s.ForwardID || generation != s.SpecRevision {
			return nil, reconcile.ErrProbeArmRejected
		}
		activationID := hex.EncodeToString(wantActivation[:])
		if currentActivation != activationID {
			return nil, reconcile.ErrProbeArmRejected
		}
		if err := snapshot.Validate(); err != nil {
			return nil, reconcile.ErrProbeArmRejected
		}
		prepared, err := a.probeMgr.PrepareProbeArm(op.Payload, s.ForwardID)
		if err != nil {
			return nil, err
		}
		token, err := act.StartProbeAdmission(activationID, s.SpecRevision)
		if err != nil {
			_ = a.probeMgr.AbortPreparedProbeArm(prepared)
			return nil, reconcile.ErrProbeArmRejected
		}
		if err := a.probeMgr.CommitPreparedProbeArmWithActivation(prepared, activationID, token.Before, token.After); err != nil {
			if rollbackErr := act.RollbackProbeAdmission(token); rollbackErr != nil {
				return nil, fmt.Errorf("agent: probe admission rollback: %w (cause: %v)", rollbackErr, err)
			}
			return nil, err
		}
		return prepared.RDY, nil
	}
	return nil, reconcile.ErrProbeArmRejected
}

// onForwardApplied maintains the orthogonal activation state machine when a
// forward is applied or hot-updated (Story 3).
func (a *App) onForwardDeleted(forwardID string) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	if a.dp == nil {
		return
	}
	a.dp.mu.Lock()
	delete(a.activations, forwardID)
	a.dp.mu.Unlock()
}

// onForwardRunError marks a listener that exited unexpectedly as unhealthy.
// The data-plane supervisor has already moved the actor to cleanupPending before
// invoking this callback, so this transition cannot claim that the listener is
// still serving traffic.
func (a *App) onForwardRunError(forwardID string, actor *forwardActor, runErr error) {
	a.probeAdmissionMu.Lock()
	if a.dp == nil {
		a.probeAdmissionMu.Unlock()
		return
	}
	a.dp.mu.Lock()
	if actor != nil {
		if current, ok := a.dp.cleanupPending[forwardID]; !ok || current != actor {
			a.dp.mu.Unlock()
			a.probeAdmissionMu.Unlock()
			return
		}
	}
	act := a.activations[forwardID]
	a.dp.mu.Unlock()
	if act == nil {
		a.probeAdmissionMu.Unlock()
		return
	}
	generation := act.Generation()
	_ = act.Update("listener_state", "ERROR", generation)
	_ = act.Update("data_plane_state", "ERROR", generation)
	state := act.Snapshot()
	var saveErr error
	if a.store != nil {
		saveErr = a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: act.ForwardID(), Activation: act.ActivationID(),
			Generation: generation, States: state,
		})
	}
	payload, marshalErr := json.Marshal(struct {
		ForwardID  string                    `json:"forward_id"`
		Activation string                    `json:"activation"`
		Generation uint64                    `json:"generation"`
		Snapshot   protocol.ActivationStates `json:"snapshot"`
	}{act.ForwardID(), act.ActivationID(), generation, state})
	client := a.client
	a.probeAdmissionMu.Unlock()

	// Cleanup callbacks may re-enter the admission path. Never invoke one while
	// probeAdmissionMu is held, or a storage failure would self-deadlock.
	if saveErr != nil {
		if a.dp.cfg.OnCleanupError != nil {
			a.dp.cfg.OnCleanupError(forwardID, actor, fmt.Errorf("save listener error state after %v: %w", runErr, saveErr))
		}
		return
	}
	if marshalErr == nil && client != nil {
		a.sendActivationStatus(context.Background(), payload)
	}
}

// onForwardCleanupError records an operational cleanup failure without
// discarding the activation mirror. cleanupPending remains the resource-owner
// source of truth until the data plane completes a later retry.
func (a *App) onForwardCleanupError(forwardID string, actor *forwardActor, cleanupErr error) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	if a.dp == nil {
		return
	}
	a.dp.mu.Lock()
	if actor != nil {
		if current, ok := a.dp.cleanupPending[forwardID]; !ok || current != actor {
			a.dp.mu.Unlock()
			return
		}
	}
	act := a.activations[forwardID]
	a.dp.mu.Unlock()
	if act == nil {
		return
	}
	generation := act.Generation()
	_ = act.Update("data_plane_state", "ERROR", generation)
	state := act.Snapshot()
	if a.store != nil {
		_ = a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: act.ForwardID(), Activation: act.ActivationID(),
			Generation: generation, States: state,
		})
	}
	_ = cleanupErr
}

func (a *App) onForwardApplied(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
	a.probeAdmissionMu.Lock()
	defer a.probeAdmissionMu.Unlock()
	if a.dp == nil || a.activations == nil {
		return
	}
	a.dp.mu.Lock()
	act, ok := a.activations[applied.ForwardID]
	if !ok {
		aid := protocol.ActivationID(applied.ForwardID, applied.SpecRevision)
		act = reconcile.NewActivation(applied.ForwardID, hex.EncodeToString(aid[:]), applied.SpecRevision)
		a.activations[applied.ForwardID] = act
	} else {
		aid := protocol.ActivationID(applied.ForwardID, applied.SpecRevision)
		activationID := hex.EncodeToString(aid[:])
		if applied.SpecRevision < act.Generation() {
			act.RestoreForGenerationWithID(applied.SpecRevision, activationID)
		} else {
			act.ResetForGenerationWithID(applied.SpecRevision, activationID)
		}
	}
	a.dp.mu.Unlock()
	if a.store != nil {
		aid := protocol.ActivationID(applied.ForwardID, applied.SpecRevision)
		activationID := hex.EncodeToString(aid[:])
		if saved, ok, err := a.store.LoadActivationSnapshot(applied.ForwardID); err == nil && ok && saved.Activation == activationID && saved.Generation == applied.SpecRevision {
			_ = act.Set(saved.States)
		}
		_ = a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: applied.ForwardID, Activation: activationID,
			Generation: applied.SpecRevision, States: act.Snapshot(),
		})
	}
}

// activation returns the tracked activation for a forward, if any.
func (a *App) activation(forwardID string) *reconcile.Activation {
	a.dp.mu.Lock()
	defer a.dp.mu.Unlock()
	return a.activations[forwardID]
}

// ActivationSnapshot returns the current orthogonal snapshot for a forward
// (nil when the forward is not applied).
func (a *App) ActivationSnapshot(forwardID string) *protocol.ActivationStates {
	act := a.activation(forwardID)
	if act == nil {
		return nil
	}
	snap := act.Snapshot()
	return &snap
}

// waitWithContext joins a lifecycle waiter without allowing a stuck transport
// implementation to ignore the caller's shutdown deadline.
func waitWithContext(ctx context.Context, wait func()) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown closes the control client, then the data plane, then the store.
// It is idempotent and honors ctx while joining transport/lifecycle workers.
func (a *App) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	a.shutdownMu.Lock()
	defer a.shutdownMu.Unlock()
	a.closeMu.Lock()
	if a.closed {
		a.closeMu.Unlock()
		return nil
	}
	// Mark shutdown admission closed before releasing the lifecycle lock. A
	// concurrent Start must not install a new runtime context while teardown is
	// waiting for an old one to drain. Keep this flag set when cleanup fails so a
	// later Shutdown can retry without allowing the app to restart half-closed.
	a.shutdownStarted = true
	a.ready.Store(false)
	cancel := a.runCancel
	a.runCancel = nil
	client := a.client
	a.closeMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if client != nil {
		if bounded, ok := client.(contextShutdownClient); ok {
			if err := bounded.ShutdownContext(ctx); err != nil {
				return fmt.Errorf("agent: wait for control shutdown: %w", err)
			}
		} else {
			// Test and legacy lifecycle clients may only expose the original
			// terminal operation; retain the context-bounded join for them.
			client.Shutdown()
			if err := waitWithContext(ctx, client.Wait); err != nil {
				return fmt.Errorf("agent: wait for control shutdown: %w", err)
			}
		}
	}
	if err := waitWithContext(ctx, a.reconnectWG.Wait); err != nil {
		return fmt.Errorf("agent: wait for reconnect loop: %w", err)
	}
	if err := waitWithContext(ctx, a.lifecycleWG.Wait); err != nil {
		return fmt.Errorf("agent: wait for liveness loop: %w", err)
	}
	if a.probeMgr != nil {
		if err := a.probeMgr.CloseContext(ctx); err != nil {
			return fmt.Errorf("agent: wait for probe manager: %w", err)
		}
	}
	if a.dp != nil {
		if err := a.dp.closeAll(ctx); err != nil {
			return fmt.Errorf("agent: close data plane: %w", err)
		}
	}
	if a.store != nil {
		if err := a.store.Close(); err != nil {
			return fmt.Errorf("agent: close localstate: %w", err)
		}
	}
	a.closeMu.Lock()
	a.closed = true
	a.closeMu.Unlock()
	return nil
}

// Store exposes the agent localstate store (tests and status).
func (a *App) Store() *localstate.Store { return a.store }

// dataPlane is the P09 direct-v4 data plane owned by the app: it opens one
// TCP listener per applied forward via the traversal PortRegistry, wraps it
// in the probe gate, and proxies with the P09 tcp.Forward.
var errDataPlaneClosing = errors.New("agent: data plane is closing")

type dataPlane struct {
	cfg                   dataPlaneConfig
	registry              *traversal.PortRegistry
	mu                    sync.Mutex
	forwards              map[string]*forwardActor
	cleanupPending        map[string]*forwardActor
	cleanupExtras         map[*forwardActor]string
	closing               bool
	supervisorWG          sync.WaitGroup
	admissionWG           sync.WaitGroup
	cleanupDrainWG        sync.WaitGroup
	cleanupDrainStarted   bool
	deletedNotified       map[string]bool
	capabilityReady       bool
	capabilityFingerprint string
}

type dataPlaneConfig struct {
	Store      *localstate.Store
	ProbeMgr   *reconcile.ProbeManager
	RouteTable traversal.RouteTable
	Clock      func() time.Time
	// OnApplied is invoked after a forward is applied or recovered, with
	// the durable applied state (the app wires the activation machine).
	OnApplied func(spec protocol.ForwardSpec, st protocol.AppliedForwardState)
	// OnDeleted is invoked after the durable deletion commit and stop attempt,
	// allowing the app to discard the activation mirror for the deleted Forward.
	OnDeleted func(forwardID string)
	// OnRunError receives a fatal listener-loop error. A listener that dies
	// unexpectedly is never silently left in the durable/live state; the actor
	// is moved to cleanupPending before the callback is invoked.
	OnRunError func(forwardID string, actor *forwardActor, err error)
	// OnCleanupError receives a cleanup error that remains retryable. It is
	// informational; ownership stays in cleanupPending until a later drain.
	OnCleanupError func(forwardID string, actor *forwardActor, err error)
}

type socketLease interface {
	Tuple() traversal.TupleKey
	Release() error
}

type forwardLifecycle interface {
	Run(context.Context) error
	CloseContext(context.Context) error
}

type forwardActor struct {
	lease   socketLease
	fwd     forwardLifecycle
	backend *forward.Backend
	stop    context.CancelFunc

	// updateFence identifies the current actor incarnation and target mutation.
	// It is guarded by dataPlane.mu and is compared by rollback before any
	// compensating target update, preventing stale operations (including ABA
	// target reuse) from clobbering a newer live actor.
	updateFence *reconcile.SideEffectFence
	updateSeq   uint64

	// cleanupMu makes every actor cleanup single-flight. A failed cleanup keeps
	// the actor in cleanupPending and a later caller may retry it; concurrent
	// callers wait for the in-flight attempt instead of closing/releasing the
	// same resources twice.
	cleanupMu                   sync.Mutex
	cleanupInProgress           bool
	cleanupDone                 chan struct{}
	cleanupComplete             bool
	cleanupErr                  error
	deleteNotificationRequested bool
	deletedNotification         bool
}

func newDataPlane(cfg dataPlaneConfig) *dataPlane {
	if cfg.RouteTable == nil {
		cfg.RouteTable = traversal.HostRouteTable{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	fingerprint, fingerprintErr := traversal.Fingerprint(cfg.RouteTable)
	_, capability, assessErr := traversal.Assess(cfg.RouteTable)
	capabilityReady := assessErr == nil && fingerprintErr == nil && capability == traversal.CapabilityDirectV4Ready
	return &dataPlane{
		cfg: cfg, registry: traversal.NewPortRegistry(), forwards: make(map[string]*forwardActor),
		cleanupPending: make(map[string]*forwardActor), cleanupExtras: make(map[*forwardActor]string),
		deletedNotified: make(map[string]bool),
		capabilityReady: capabilityReady, capabilityFingerprint: fingerprint,
	}
}

// startCleanupDrain retries cleanup for actors that still own a listener or
// registry lease after a failed stop. It has its own wait group so App.Shutdown
// never closes localstate while a retry callback can still access it.
func (d *dataPlane) startCleanupDrain(parent context.Context) {
	if parent == nil {
		parent = context.Background()
	}
	d.mu.Lock()
	if d.cleanupDrainStarted {
		d.mu.Unlock()
		return
	}
	d.cleanupDrainStarted = true
	d.cleanupDrainWG.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.cleanupDrainWG.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			drainCtx, cancel := context.WithTimeout(parent, 5*time.Second)
			drainCleanupErr := d.drainCleanup(drainCtx)
			cancel()
			_ = drainCleanupErr
			d.mu.Lock()
			closing := d.closing
			d.mu.Unlock()
			if closing {
				return
			}
			select {
			case <-parent.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// drainCleanup takes a pointer-identity snapshot so two actors with the same
// Forward ID cannot overwrite one another in the cleanup maps or lose a lease.
func (d *dataPlane) drainCleanup(ctx context.Context) error {
	actors := d.cleanupActorsSnapshot()
	var firstErr error
	for _, item := range actors {
		if err := d.cleanupActor(ctx, item.forwardID, item.actor); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type cleanupItem struct {
	forwardID string
	actor     *forwardActor
}

func (d *dataPlane) cleanupActorsSnapshot() []cleanupItem {
	d.mu.Lock()
	defer d.mu.Unlock()
	seen := make(map[*forwardActor]bool, len(d.cleanupPending)+len(d.cleanupExtras))
	items := make([]cleanupItem, 0, len(d.cleanupPending)+len(d.cleanupExtras))
	for id, actor := range d.cleanupPending {
		if actor == nil || seen[actor] {
			continue
		}
		seen[actor] = true
		items = append(items, cleanupItem{forwardID: id, actor: actor})
	}
	for actor, id := range d.cleanupExtras {
		if actor == nil || seen[actor] {
			continue
		}
		seen[actor] = true
		items = append(items, cleanupItem{forwardID: id, actor: actor})
	}
	return items
}

func (d *dataPlane) addCleanupPendingLocked(forwardID string, actor *forwardActor) {
	if actor == nil {
		return
	}
	if current, ok := d.cleanupPending[forwardID]; !ok {
		d.cleanupPending[forwardID] = actor
	} else if current != actor {
		d.cleanupExtras[actor] = forwardID
	}
}

func (d *dataPlane) removeCleanupPendingLocked(forwardID string, actor *forwardActor) {
	if current, ok := d.cleanupPending[forwardID]; ok && current == actor {
		delete(d.cleanupPending, forwardID)
		return
	}
	if id, ok := d.cleanupExtras[actor]; ok && id == forwardID {
		delete(d.cleanupExtras, actor)
	}
}

func (d *dataPlane) pendingActorsLocked(forwardID string) []cleanupItem {
	var items []cleanupItem
	if actor := d.cleanupPending[forwardID]; actor != nil {
		items = append(items, cleanupItem{forwardID: forwardID, actor: actor})
	}
	for actor, id := range d.cleanupExtras {
		if id == forwardID {
			items = append(items, cleanupItem{forwardID: forwardID, actor: actor})
		}
	}
	return items
}

// beginAdmission reserves an in-flight apply/reopen operation before it leaves
// the data-plane mutex. closeAll sets closing while holding that same mutex, so
// it is safe to wait for every admitted operation before taking its ownership
// snapshot.
func (d *dataPlane) beginAdmission() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing {
		return false
	}
	d.admissionWG.Add(1)
	return true
}

func (d *dataPlane) notifyDeleted(forwardID string) {
	d.mu.Lock()
	if d.deletedNotified == nil {
		d.deletedNotified = make(map[string]bool)
	}
	if d.deletedNotified[forwardID] {
		d.mu.Unlock()
		return
	}
	d.deletedNotified[forwardID] = true
	onDeleted := d.cfg.OnDeleted
	d.mu.Unlock()
	if onDeleted != nil {
		onDeleted(forwardID)
	}
}

func (d *dataPlane) capabilityCheck() error {
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		return errDataPlaneClosing
	}
	ready := d.capabilityReady
	fingerprint := d.capabilityFingerprint
	d.mu.Unlock()
	if !ready {
		return reconcile.ErrCapabilityLost
	}
	_, capability, assessErr := traversal.Assess(d.cfg.RouteTable)
	if assessErr != nil || capability != traversal.CapabilityDirectV4Ready {
		return reconcile.ErrCapabilityLost
	}
	if fingerprint != "" {
		currentFingerprint, err := traversal.Fingerprint(d.cfg.RouteTable)
		if err != nil || currentFingerprint != fingerprint {
			return reconcile.ErrCapabilityLost
		}
	}
	return nil
}

// apply implements reconcile.ApplyHook: it opens (or hot-updates) one
// direct-v4 forward and returns the durable applied state.
func (d *dataPlane) apply(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
	if !d.beginAdmission() {
		return protocol.AppliedForwardState{}, errDataPlaneClosing
	}
	defer d.admissionWG.Done()

	pendingDelete, tombstoned, err := readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if fenceErr := forwardDeleteFenceError(spec.ForwardID, pendingDelete, tombstoned); fenceErr != nil {
		return protocol.AppliedForwardState{}, fenceErr
	}

	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, errDataPlaneClosing
	}
	pending := d.pendingActorsLocked(spec.ForwardID)
	d.mu.Unlock()
	for _, item := range pending {
		if err := d.cleanupActor(ctx, item.forwardID, item.actor); err != nil {
			return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q cleanup is still pending: %w", spec.ForwardID, err)
		}
	}
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, errDataPlaneClosing
	}
	if pending := d.pendingActorsLocked(spec.ForwardID); len(pending) != 0 {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q cleanup is still pending", spec.ForwardID)
	}
	if actor, ok := d.forwards[spec.ForwardID]; ok {
		// A delete fence may have been installed after initial admission. Check
		// again before mutating an existing actor as well as before new installs.
		pendingDelete, tombstoned, err = readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
		if err != nil {
			d.mu.Unlock()
			return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
		}
		if fenceErr := forwardDeleteFenceError(spec.ForwardID, pendingDelete, tombstoned); fenceErr != nil {
			d.mu.Unlock()
			return protocol.AppliedForwardState{}, fenceErr
		}
		if !d.capabilityReady {
			d.mu.Unlock()
			return protocol.AppliedForwardState{}, reconcile.ErrCapabilityLost
		}
		// Hot update: the listener stays, the backend target swaps
		// atomically; new sessions resolve the new snapshot at accept time.
		if err := actor.backend.Update(spec.Target); err != nil {
			d.mu.Unlock()
			return protocol.AppliedForwardState{}, err
		}
		actor.updateSeq++
		if fence := reconcile.SideEffectFenceFromContext(ctx); fence != nil {
			fence.SetValue(actor.updateFenceToken(actor.updateSeq))
		}
		st := appliedState(spec, actor.lease.Tuple(), d.cfg.Clock)
		onApplied := d.cfg.OnApplied
		d.mu.Unlock()
		if onApplied != nil {
			onApplied(spec, st)
		}
		return st, nil
	}

	if !d.capabilityReady {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, reconcile.ErrCapabilityLost
	}

	// Re-check the durable fence immediately before acquiring a listener. A
	// concurrent delete may have installed its intent after initial admission.
	pendingDelete, tombstoned, err = readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if fenceErr := forwardDeleteFenceError(spec.ForwardID, pendingDelete, tombstoned); fenceErr != nil {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fenceErr
	}

	if spec.Strategy != protocol.StrategyDirectV4 {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: strategy %q not supported by the M1 data plane", spec.Strategy)
	}
	sel, capability, assessErr := traversal.Assess(d.cfg.RouteTable)
	if assessErr != nil || capability != traversal.CapabilityDirectV4Ready {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, traversal.NewCapabilityError(capability, assessErr)
	}
	actor, err := d.newForwardActor(ctx, spec, sel.Source.String(), spec.RequestedLocalPort)
	if err != nil {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, err
	}
	lease := actor.lease
	// The delete fence can be installed while the OS listener is being
	// acquired. Re-check before constructing and publishing the actor, and
	// release the lease if deletion won the race.
	pendingDelete, tombstoned, err = readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		_ = lease.Release()
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if fenceErr := forwardDeleteFenceError(spec.ForwardID, pendingDelete, tombstoned); fenceErr != nil {
		_ = lease.Release()
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fenceErr
	}
	runCtx, cancel := context.WithCancel(context.Background())
	actor.stop = cancel
	// Re-check immediately before actor installation. The fence is durable and
	// independent of the data-plane mutex, so deletion may win while backend and
	// forwarding resources are being constructed.
	pendingDelete, tombstoned, err = readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		cancel()
		_ = actor.fwd.CloseContext(context.Background())
		_ = lease.Release()
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if fenceErr := forwardDeleteFenceError(spec.ForwardID, pendingDelete, tombstoned); fenceErr != nil {
		cancel()
		_ = actor.fwd.CloseContext(context.Background())
		_ = lease.Release()
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, fenceErr
	}
	d.forwards[spec.ForwardID] = actor
	d.startForwardSupervisor(runCtx, spec.ForwardID, actor)
	st := appliedState(spec, lease.Tuple(), d.cfg.Clock)
	onApplied := d.cfg.OnApplied
	d.mu.Unlock()
	if onApplied != nil {
		onApplied(spec, st)
	}
	return st, nil
}

func (d *dataPlane) newForwardActor(ctx context.Context, spec protocol.ForwardSpec, address string, port uint16) (*forwardActor, error) {
	backend, err := forward.NewBackend(spec.Target)
	if err != nil {
		return nil, err
	}
	key := traversal.TupleKey{Address: address, Port: port, Family: "ipv4", Protocol: string(spec.Protocol)}
	switch spec.Protocol {
	case protocol.ProtocolTCP:
		lease, err := d.registry.Acquire(ctx, spec.ForwardID, key)
		if err != nil {
			return nil, err
		}
		gate := reconcile.NewProbeGate(lease.Listener, d.cfg.ProbeMgr, reconcile.ProbeGateOptions{ForwardID: spec.ForwardID, ReadTimeout: 2 * time.Second})
		fwd, err := tcp.New(gate, tcp.Options{Backend: backend, DialTimeout: 5 * time.Second})
		if err != nil {
			_ = lease.Release()
			return nil, err
		}
		return &forwardActor{lease: lease, fwd: fwd, backend: backend, updateFence: reconcile.NewSideEffectFence()}, nil
	case protocol.ProtocolUDP:
		lease, err := d.registry.AcquireUDP(ctx, spec.ForwardID, key)
		if err != nil {
			return nil, err
		}
		// One socket-independent classifier routes full-match WAN1 probes through
		// the existing durable ProbeManager; the single ingress reader owns the
		// ACK write and only then marks ACK/receipt transport delivery.
		probeMgr := d.cfg.ProbeMgr
		classifier := udpforward.ClassifierFunc(func(p udpforward.Packet) udpforward.Classification {
			if probeMgr == nil {
				return udpforward.Classification{}
			}
			res := probeMgr.HandleUDPProbe(spec.ForwardID, p.Source, p.Data)
			if !res.Matched {
				return udpforward.Classification{}
			}
			return udpforward.Classification{
				Matched: true,
				Reply:   res.ACK,
				OnReply: func(err error) {
					if err != nil {
						return
					}
					_ = probeMgr.MarkUDPProbeACKSent(res.ProbeID)
					probeMgr.SendUDPProbeReceipt(res)
				},
			}
		})
		fwd, err := udpforward.New(lease.Conn, udpforward.Options{Backend: backend, DialTimeout: 5 * time.Second, Classifiers: []udpforward.Classifier{classifier}})
		if err != nil {
			_ = lease.Release()
			return nil, err
		}
		return &forwardActor{lease: lease, fwd: fwd, backend: backend, updateFence: reconcile.NewSideEffectFence()}, nil
	default:
		return nil, fmt.Errorf("agent: protocol %q not supported by direct-v4 data plane", spec.Protocol)
	}
}

// actorUpdateFence is the compare-and-swap token for one accepted target
// mutation. The actor pointer is part of the token, so a replacement actor with
// the same ForwardID cannot satisfy an old rollback. Sequence fencing also
// rejects ABA target transitions (A -> B -> A).
type actorUpdateFence struct {
	actor *forwardActor
	seq   uint64
}

func (a *forwardActor) updateFenceToken(seq uint64) actorUpdateFence {
	return actorUpdateFence{actor: a, seq: seq}
}

// rollback restores an existing actor only when the corresponding apply is
// still the actor's latest mutation. A stale compensation is rejected before
// touching the backend or activation callback.
func (d *dataPlane) rollback(ctx context.Context, previous protocol.ForwardSpec, applied protocol.AppliedForwardState) error {
	fence := reconcile.SideEffectFenceFromContext(ctx)
	if fence == nil {
		return d.rollbackLegacy(ctx, previous, applied)
	}
	token, ok := fence.Value().(actorUpdateFence)
	if !ok || token.actor == nil || token.seq == 0 {
		return fmt.Errorf("%w: forward %q has no valid actor update fence", reconcile.ErrStaleSideEffect, previous.ForwardID)
	}
	d.mu.Lock()
	actor, current := d.forwards[previous.ForwardID]
	if !current || actor != token.actor || actor.updateSeq != token.seq {
		d.mu.Unlock()
		return fmt.Errorf("%w: forward %q was superseded", reconcile.ErrStaleSideEffect, previous.ForwardID)
	}
	if err := actor.backend.Update(previous.Target); err != nil {
		d.mu.Unlock()
		return err
	}
	actor.updateSeq++
	fence.SetValue(actor.updateFenceToken(actor.updateSeq))
	onApplied := d.cfg.OnApplied
	d.mu.Unlock()
	if onApplied != nil {
		onApplied(previous, applied)
	}
	return nil
}

// rollbackLegacy keeps direct package-local callers compatible while making
// all reconcile-issued compensation use the fenced path above.
func (d *dataPlane) rollbackLegacy(ctx context.Context, previous protocol.ForwardSpec, applied protocol.AppliedForwardState) error {
	_ = ctx
	d.mu.Lock()
	actor, ok := d.forwards[previous.ForwardID]
	if !ok {
		d.mu.Unlock()
		return nil
	}
	if err := actor.backend.Update(previous.Target); err != nil {
		d.mu.Unlock()
		return err
	}
	actor.updateSeq++
	onApplied := d.cfg.OnApplied
	d.mu.Unlock()
	if onApplied != nil {
		onApplied(previous, applied)
	}
	return nil
}

// startForwardSupervisor owns the accept loop for one actor. A normal
// cancellation or listener close is part of cleanup; every other return is a
// fatal listener failure and is demoted before the error callback runs.
func (d *dataPlane) startForwardSupervisor(ctx context.Context, forwardID string, actor *forwardActor) {
	if actor == nil || actor.fwd == nil {
		return
	}
	d.supervisorWG.Add(1)
	go func() {
		defer d.supervisorWG.Done()
		err := actor.fwd.Run(ctx)
		if err == nil || errors.Is(err, context.Canceled) {
			return
		}
		d.handleForwardRunError(forwardID, actor, err)
	}()
}

func (d *dataPlane) handleForwardRunError(forwardID string, actor *forwardActor, runErr error) {
	d.mu.Lock()
	owned := false
	if current, ok := d.forwards[forwardID]; ok && current == actor {
		delete(d.forwards, forwardID)
		d.addCleanupPendingLocked(forwardID, actor)
		owned = true
	}
	d.mu.Unlock()
	if owned && d.cfg.OnRunError != nil {
		d.cfg.OnRunError(forwardID, actor, runErr)
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = d.cleanupActor(cleanupCtx, forwardID, actor)
}

// cleanupActor is the sole owner of Forward/lease teardown. The actor remains
// in cleanupPending until both resources report success; a deadline only ends
// this attempt and never discards ownership.
func (d *dataPlane) cleanupActor(ctx context.Context, forwardID string, actor *forwardActor) error {
	if actor == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	actor.cleanupMu.Lock()
	if actor.cleanupComplete {
		err := actor.cleanupErr
		actor.cleanupMu.Unlock()
		return err
	}
	if actor.cleanupInProgress {
		done := actor.cleanupDone
		actor.cleanupMu.Unlock()
		select {
		case <-done:
			actor.cleanupMu.Lock()
			err := actor.cleanupErr
			actor.cleanupMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	actor.cleanupInProgress = true
	actor.cleanupDone = make(chan struct{})
	done := actor.cleanupDone
	actor.cleanupMu.Unlock()

	var cleanupErr error
	if actor.stop != nil {
		actor.stop()
	}
	if actor.fwd != nil {
		cleanupErr = actor.fwd.CloseContext(ctx)
	}
	if cleanupErr == nil && actor.lease != nil {
		cleanupErr = actor.lease.Release()
	}

	actor.cleanupMu.Lock()
	actor.cleanupErr = cleanupErr
	actor.cleanupInProgress = false
	if cleanupErr == nil {
		actor.cleanupComplete = true
	}
	close(done)
	actor.cleanupMu.Unlock()

	if cleanupErr != nil {
		if d.cfg.OnCleanupError != nil {
			d.cfg.OnCleanupError(forwardID, actor, cleanupErr)
		}
		return cleanupErr
	}
	d.mu.Lock()
	d.removeCleanupPendingLocked(forwardID, actor)
	d.mu.Unlock()
	actor.cleanupMu.Lock()
	deleteNotification := actor.deleteNotificationRequested && !actor.deletedNotification
	if deleteNotification {
		actor.deletedNotification = true
	}
	actor.cleanupMu.Unlock()
	if deleteNotification && d.cfg.OnDeleted != nil {
		d.cfg.OnDeleted(forwardID)
	}
	return nil
}

// markCapabilityLost stops every data-plane actor before any remap/reprobe and
// records a one-shot transition for the liveness watcher.
func (d *dataPlane) markCapabilityLost(ctx context.Context) bool {
	d.mu.Lock()
	if !d.capabilityReady {
		d.mu.Unlock()
		return false
	}
	d.capabilityReady = false
	actors := make(map[string]*forwardActor, len(d.forwards))
	for id, actor := range d.forwards {
		actors[id] = actor
		delete(d.forwards, id)
		d.addCleanupPendingLocked(id, actor)
	}
	d.mu.Unlock()
	for id, actor := range actors {
		cleanupCtx := ctx
		if cleanupCtx == nil {
			cleanupCtx = context.Background()
		}
		attemptCtx, cancel := context.WithTimeout(cleanupCtx, 5*time.Second)
		_ = d.cleanupActor(attemptCtx, id, actor)
		cancel()
	}
	return true
}

// capabilityChanged reports a new route/interface identity while the data
// plane still believes its previous capability is ready.
func (d *dataPlane) capabilityChanged(fingerprint string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.capabilityReady && d.capabilityFingerprint != "" && fingerprint != "" && d.capabilityFingerprint != fingerprint
}

// markCapabilityRestored returns true once per loss->restore transition and
// records the route/interface identity that the recovered listeners use.
func (d *dataPlane) markCapabilityRestored(fingerprint string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.capabilityReady {
		return false
	}
	d.capabilityReady = true
	d.capabilityFingerprint = fingerprint
	return true
}

// stop implements reconcile.StopHook: it stops one forward's actor. The
// actor remains owned by cleanupPending until both the listener and lease have
// completed cleanup; a caller deadline never discards that ownership.
func (d *dataPlane) stop(ctx context.Context, forwardID string) error {
	d.mu.Lock()
	actor, ok := d.forwards[forwardID]
	if ok {
		delete(d.forwards, forwardID)
		d.addCleanupPendingLocked(forwardID, actor)
	}
	pending := d.pendingActorsLocked(forwardID)
	d.mu.Unlock()
	if !ok && len(pending) == 0 {
		// There is no live actor to stop, but a durable deletion still needs its
		// activation mirror removed. Repeated deletion delivery is idempotent.
		d.notifyDeleted(forwardID)
		return nil
	}
	var cleanupErr error
	if ok {
		actor.cleanupMu.Lock()
		actor.deleteNotificationRequested = true
		actor.cleanupMu.Unlock()
		cleanupErr = d.cleanupActor(ctx, forwardID, actor)
	}
	for _, item := range pending {
		item.actor.cleanupMu.Lock()
		item.actor.deleteNotificationRequested = true
		item.actor.cleanupMu.Unlock()
		if err := d.cleanupActor(ctx, item.forwardID, item.actor); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if cleanupErr == nil {
		d.notifyDeleted(forwardID)
	}
	return cleanupErr
}

// recover reopens a listener for every durably applied PRESENT forward
// (restart path, Story 6). The applied record contains the complete serving
// spec and is the only target source used here. Received desired state may be
// newer after a PARTIAL apply and must remain retry intent, never recovery
// input for the last-known-good listener.
func (d *dataPlane) recover(ctx context.Context) error {
	if !d.beginAdmission() {
		return errDataPlaneClosing
	}
	defer d.admissionWG.Done()
	if d.cfg.Store == nil {
		return nil
	}
	// Received desired state is retry intent, not the source of the serving
	// target. Recovery is fenced by durable deletion facts, rather than assuming
	// a received snapshot contains an explicit ABSENT entry.
	records, err := d.cfg.Store.ListAppliedRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		pendingDelete, tombstoned, err := readForwardDeleteFence(d.cfg.Store, record.State.ForwardID)
		if err != nil {
			return fmt.Errorf("agent: forward %q delete fence: %w", record.State.ForwardID, err)
		}
		if pendingDelete || tombstoned {
			// A durable delete fence wins over every applied LKG row, including
			// rows retained across a crash before listener cleanup completed.
			continue
		}
		if !record.HasServingSpec {
			// Legacy rows predate durable serving-target persistence. They remain
			// valid for inspection/probe checks, but reopening from a guessed
			// desired target would be unsafe, so leave them quarantined.
			continue
		}
		if !recoveryRevisionMatches(record.ServingSpec, record.State) {
			continue
		}
		d.mu.Lock()
		_, exists := d.forwards[record.State.ForwardID]
		d.mu.Unlock()
		if exists {
			continue
		}
		if err := d.reopen(ctx, record.ServingSpec, record.State); err != nil {
			return err
		}
	}
	return nil
}

func recoveryRevisionMatches(spec protocol.ForwardSpec, st protocol.AppliedForwardState) bool {
	// DesiredRevision may be ahead of SpecRevision after a PARTIAL apply. The
	// serving spec is bound to the applied SpecRevision; the newer desired
	// revision remains retry intent and must never replace this LKG target.
	return spec.Presence == protocol.PresencePresent &&
		spec.ForwardID == st.ForwardID &&
		spec.DesiredRevision == st.SpecRevision
}

// reopen restores one forward's actor from its durable serving spec.
func (d *dataPlane) reopen(ctx context.Context, spec protocol.ForwardSpec, st protocol.AppliedForwardState) error {
	if !recoveryRevisionMatches(spec, st) {
		return nil
	}
	pendingDelete, tombstoned, err := readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		return fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if pendingDelete || tombstoned {
		return nil
	}

	sel, capability, assessErr := traversal.Assess(d.cfg.RouteTable)
	if assessErr != nil || capability != traversal.CapabilityDirectV4Ready {
		return traversal.NewCapabilityError(capability, assessErr)
	}
	// The durable tuple is evidence of the previous bind, not an instruction
	// to reopen a stale source. Re-select the current direct-v4 source after a
	// route/interface change and request the desired port when one was pinned.
	port := spec.RequestedLocalPort
	if port == 0 {
		port = st.ActualBindPort
	}
	actor, err := d.newForwardActor(ctx, spec, sel.Source.String(), port)
	if err != nil {
		return err
	}
	lease := actor.lease
	// Re-check after listener acquisition so a concurrent durable delete cannot
	// be followed by actor construction or publication.
	pendingDelete, tombstoned, err = readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		_ = lease.Release()
		return fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if pendingDelete || tombstoned {
		_ = lease.Release()
		return nil
	}
	runCtx, cancel := context.WithCancel(context.Background())
	actor.stop = cancel
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		cancel()
		_ = actor.fwd.CloseContext(context.Background())
		_ = lease.Release()
		return errDataPlaneClosing
	}
	// A fence may be installed while the listener and actor are being built.
	// Check once more under the install lock before making the actor reachable.
	pendingDelete, tombstoned, err = readForwardDeleteFence(d.cfg.Store, spec.ForwardID)
	if err != nil {
		d.mu.Unlock()
		cancel()
		_ = actor.fwd.CloseContext(context.Background())
		_ = lease.Release()
		return fmt.Errorf("agent: forward %q delete fence: %w", spec.ForwardID, err)
	}
	if pendingDelete || tombstoned {
		d.mu.Unlock()
		cancel()
		_ = actor.fwd.CloseContext(context.Background())
		_ = lease.Release()
		return nil
	}
	if _, exists := d.forwards[spec.ForwardID]; exists || len(d.pendingActorsLocked(spec.ForwardID)) != 0 {
		d.mu.Unlock()
		cancel()
		_ = actor.fwd.CloseContext(context.Background())
		_ = lease.Release()
		return nil
	}
	d.forwards[spec.ForwardID] = actor
	d.startForwardSupervisor(runCtx, spec.ForwardID, actor)
	d.mu.Unlock()
	if d.cfg.OnApplied != nil {
		d.cfg.OnApplied(spec, appliedState(spec, lease.Tuple(), d.cfg.Clock))
	}
	return nil
}

func (d *dataPlane) closeAll(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Close the admission gate before taking ownership. An admitted apply or
	// recovery may still be constructing a listener; waiting first lets it
	// finish under the same lifecycle context, after which its actor is included
	// in the ownership snapshot below.
	d.mu.Lock()
	d.closing = true
	d.mu.Unlock()
	if err := waitWithContext(ctx, d.admissionWG.Wait); err != nil {
		return fmt.Errorf("agent: wait for data-plane admission: %w", err)
	}

	d.mu.Lock()
	for id, actor := range d.forwards {
		delete(d.forwards, id)
		d.addCleanupPendingLocked(id, actor)
	}
	d.mu.Unlock()

	var cleanupErr error
	actors := d.cleanupActorsSnapshot()
	for _, item := range actors {
		if err := d.cleanupActor(ctx, item.forwardID, item.actor); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("cleanup forward %q: %w", item.forwardID, err))
		}
	}
	// Forward.CloseContext normally joins its Run goroutine, but the explicit
	// join also covers actors whose listener was already externally closed or
	// whose test double has no close wake-up guarantee.
	if err := waitWithContext(ctx, d.supervisorWG.Wait); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("agent: wait for forward supervisors: %w", err))
	}
	if err := waitWithContext(ctx, d.cleanupDrainWG.Wait); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("agent: wait for cleanup drain: %w", err))
	}
	return cleanupErr
}

func appliedState(spec protocol.ForwardSpec, tuple traversal.TupleKey, clock func() time.Time) protocol.AppliedForwardState {
	return protocol.AppliedForwardState{
		ForwardID:       spec.ForwardID,
		SpecRevision:    spec.DesiredRevision,
		DesiredRevision: spec.DesiredRevision,
		ActualBindHost:  tuple.Address,
		ActualBindPort:  tuple.Port,
		Strategy:        string(spec.Strategy),
		LayerVersion:    1,
		AppliedAtUnix:   clock().Unix(),
	}
}
