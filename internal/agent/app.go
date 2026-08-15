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

	client     *control.Client
	reconciler *reconcile.Reconciler
	probeMgr   *reconcile.ProbeManager
	dp         *dataPlane

	// activations tracks the orthogonal activation state machine per applied
	// forward (Story 3). The map is guarded by dp.mu.
	activations map[string]*reconcile.Activation

	ready atomic.Bool

	closeMu     sync.Mutex
	closed      bool
	reconnectWG sync.WaitGroup
	runCancel   context.CancelFunc
	lifecycleWG sync.WaitGroup
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
	a := &App{cfg: cfg}

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
		SendControl: func(ctx context.Context, messageType string, payload []byte) error {
			if a.client == nil {
				return errors.New("agent: control client not started")
			}
			return a.client.SendMessage(ctx, messageType, payload)
		},
	})

	a.dp = newDataPlane(dataPlaneConfig{
		Store:      st,
		ProbeMgr:   a.probeMgr,
		RouteTable: cfg.RouteTable,
		Clock:      cfg.Clock,
		OnApplied: func(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
			a.onForwardApplied(spec, applied)
		},
	})
	a.activations = make(map[string]*reconcile.Activation)

	a.reconciler = reconcile.New(st, localstate.NewLatch(), localstate.MarkerActive,
		a.dp.apply, a.dp.stop)

	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  cfg.Endpoint,
		NodeID:    cfg.NodeID,
		Store:     st,
		Key:       key,
		Heartbeat: cfg.Heartbeat,
		OnCommand: a.handleCommand,
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
// session handshake completes. It blocks until the first connect succeeds
// or ctx is done; the session and all loops run on ctx, so the caller must
// keep ctx alive for the app's lifetime (Shutdown cancels the client).
func (a *App) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, runCancel := context.WithCancel(ctx)
	a.closeMu.Lock()
	a.runCancel = runCancel
	a.closeMu.Unlock()
	if err := a.client.Connect(runCtx); err != nil {
		runCancel()
		a.client.Shutdown()
		a.client.Wait()
		a.dp.closeAll()
		a.probeMgr.Close()
		_ = a.store.Close()
		return fmt.Errorf("agent: control connect: %w", err)
	}
	a.probeMgr.Start(runCtx)
	// A receipt may have been durably recorded immediately before a crash or
	// control disconnect. Retry it after the new session is established.
	if err := a.probeMgr.RetryPendingReceipts(runCtx); err != nil {
		runCancel()
		a.client.Shutdown()
		a.client.Wait()
		a.dp.closeAll()
		a.probeMgr.Close()
		_ = a.store.Close()
		return fmt.Errorf("agent: retry pending probe receipts: %w", err)
	}
	a.replayActivationStatuses(runCtx)
	// Restart recovery: reopen listeners for durably applied forwards
	// (Story 6: restart restores the listener, initially UNVERIFIED).
	if err := a.dp.recover(runCtx); err != nil {
		runCancel()
		a.client.Shutdown()
		a.dp.closeAll()
		a.probeMgr.Close()
		_ = a.store.Close()
		return fmt.Errorf("agent: data plane recovery: %w", err)
	}
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
	a.ready.Store(true)
	return nil
}

// replayActivationStatuses re-sends persisted evidence-loss mirrors after a
// reconnect. The status message is idempotent and the controller applies its
// activation CAS before replacing the runtime row.
func (a *App) replayActivationStatuses(ctx context.Context) {
	if a.store == nil || a.client == nil {
		return
	}
	snapshots, err := a.store.ListActivationSnapshots(256)
	if err != nil {
		return
	}
	for _, snapshot := range snapshots {
		if snapshot.States.PublicationState != "STALE" && snapshot.States.PublicationState != "UNPUBLISHED" {
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
	for {
		a.client.Wait()
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := a.client.Connect(ctx); err != nil {
			if strings.Contains(err.Error(), "client is closed") || ctx.Err() != nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if err := a.probeMgr.RetryPendingReceipts(ctx); err != nil {
			a.ready.Store(false)
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
			_, capability, err := traversal.Assess(a.cfg.RouteTable)
			available := err == nil && capability == traversal.CapabilityDirectV4Ready
			if !available {
				if a.dp.markCapabilityLost() {
					a.markEvidenceLost(ctx)
				}
				continue
			}
			if a.dp.markCapabilityRestored() {
				if err := a.dp.recover(ctx); err != nil {
					// Keep the capability degraded so the next poll retries
					// recovery, without claiming a listener is active.
					a.dp.markCapabilityLost()
				}
			}
		}
	}
}

func (a *App) markEvidenceLost(ctx context.Context) {
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
	switch op.MessageType {
	case "desired":
		return a.applyDesired(ctx, op)
	case "probe_arm":
		return a.armProbe(ctx, op)
	case "forward_delete":
		return a.applyDesired(ctx, op)
	default:
		return nil, fmt.Errorf("agent: unexpected command type %q", op.MessageType)
	}
}

// applyDesired reconciles a desired snapshot through the data plane and
// returns the durable apply report as the command result.
func (a *App) applyDesired(ctx context.Context, op control.Operation) ([]byte, error) {
	var d protocol.DesiredState
	if err := json.Unmarshal(op.Payload, &d); err != nil {
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
	arm, err := protocol.ParseProbeArm(op.Payload)
	if err != nil {
		return nil, err
	}
	// Resolve the forward whose applied activation matches the arm.
	states, err := a.store.ListAppliedStates()
	if err != nil {
		return nil, err
	}
	for _, s := range states {
		if arm.Activation == protocol.ActivationID(s.ForwardID, s.SpecRevision) {
			rdy, err := a.probeMgr.HandleProbeArm(ctx, op.Payload, s.ForwardID)
			if err != nil {
				return nil, err
			}
			// Story 3: entering a probe cycle unpublishes and marks the WAN
			// axis PROBING before the provider is ever contacted.
			if act := a.activation(s.ForwardID); act != nil {
				_ = act.StartProbe(act.Generation())
			}
			return rdy, nil
		}
	}
	return nil, reconcile.ErrProbeArmRejected
}

// onForwardApplied maintains the orthogonal activation state machine when a
// forward is applied or hot-updated (Story 3).
func (a *App) onForwardApplied(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
	a.dp.mu.Lock()
	act, ok := a.activations[applied.ForwardID]
	if !ok {
		aid := protocol.ActivationID(applied.ForwardID, applied.SpecRevision)
		act = reconcile.NewActivation(applied.ForwardID, hex.EncodeToString(aid[:]), applied.SpecRevision)
		a.activations[applied.ForwardID] = act
	} else {
		act.ResetForGeneration(applied.SpecRevision)
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

// Shutdown closes the control client, then the data plane, then the store.
// It is idempotent.
func (a *App) Shutdown(ctx context.Context) error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	a.ready.Store(false)
	if a.runCancel != nil {
		a.runCancel()
		a.runCancel = nil
	}
	if a.client != nil {
		a.client.Shutdown()
		a.client.Wait()
	}
	a.reconnectWG.Wait()
	a.lifecycleWG.Wait()
	if a.probeMgr != nil {
		a.probeMgr.Close()
	}
	if a.dp != nil {
		a.dp.closeAll()
	}
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}

// Store exposes the agent localstate store (tests and status).
func (a *App) Store() *localstate.Store { return a.store }

// dataPlane is the P09 direct-v4 data plane owned by the app: it opens one
// TCP listener per applied forward via the traversal PortRegistry, wraps it
// in the probe gate, and proxies with the P09 tcp.Forward.
type dataPlane struct {
	cfg             dataPlaneConfig
	registry        *traversal.PortRegistry
	mu              sync.Mutex
	forwards        map[string]*forwardActor
	capabilityReady bool
}

type dataPlaneConfig struct {
	Store      *localstate.Store
	ProbeMgr   *reconcile.ProbeManager
	RouteTable traversal.RouteTable
	Clock      func() time.Time
	// OnApplied is invoked after a forward is applied or recovered, with
	// the durable applied state (the app wires the activation machine).
	OnApplied func(spec protocol.ForwardSpec, st protocol.AppliedForwardState)
}

type forwardActor struct {
	lease   *traversal.Lease
	fwd     *tcp.Forward
	backend *forward.Backend
	stop    context.CancelFunc
}

func newDataPlane(cfg dataPlaneConfig) *dataPlane {
	if cfg.RouteTable == nil {
		cfg.RouteTable = traversal.HostRouteTable{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &dataPlane{cfg: cfg, registry: traversal.NewPortRegistry(), forwards: make(map[string]*forwardActor), capabilityReady: true}
}

// apply implements reconcile.ApplyHook: it opens (or hot-updates) one
// direct-v4 forward and returns the durable applied state.
func (d *dataPlane) apply(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
	d.mu.Lock()
	if actor, ok := d.forwards[spec.ForwardID]; ok {
		// Hot update: the listener stays, the backend target swaps
		// atomically; new sessions resolve the new snapshot at accept time.
		if err := actor.backend.Update(spec.Target); err != nil {
			d.mu.Unlock()
			return protocol.AppliedForwardState{}, err
		}
		st := appliedState(spec, actor.lease, d.cfg.Clock)
		onApplied := d.cfg.OnApplied
		d.mu.Unlock()
		if onApplied != nil {
			onApplied(spec, st)
		}
		return st, nil
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
	lease, err := d.registry.Acquire(ctx, spec.ForwardID, traversal.TupleKey{
		Address:  sel.Source.String(),
		Port:     spec.RequestedLocalPort,
		Family:   "ipv4",
		Protocol: "tcp",
	})
	if err != nil {
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, err
	}
	gate := reconcile.NewProbeGate(lease.Listener, d.cfg.ProbeMgr, reconcile.ProbeGateOptions{
		ForwardID:   spec.ForwardID,
		ReadTimeout: 2 * time.Second,
	})
	backend, err := forward.NewBackend(spec.Target)
	if err != nil {
		_ = lease.Release()
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, err
	}
	fwd, err := tcp.New(gate, tcp.Options{Backend: backend, DialTimeout: 5 * time.Second})
	if err != nil {
		_ = lease.Release()
		d.mu.Unlock()
		return protocol.AppliedForwardState{}, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	go fwd.Run(runCtx)
	d.forwards[spec.ForwardID] = &forwardActor{lease: lease, fwd: fwd, backend: backend, stop: cancel}
	st := appliedState(spec, lease, d.cfg.Clock)
	onApplied := d.cfg.OnApplied
	d.mu.Unlock()
	if onApplied != nil {
		onApplied(spec, st)
	}
	return st, nil
}

// markCapabilityLost stops every data-plane actor before any remap/reprobe and
// records a one-shot transition for the liveness watcher.
func (d *dataPlane) markCapabilityLost() bool {
	d.mu.Lock()
	if !d.capabilityReady {
		d.mu.Unlock()
		return false
	}
	d.capabilityReady = false
	actors := make([]*forwardActor, 0, len(d.forwards))
	for id, actor := range d.forwards {
		actors = append(actors, actor)
		delete(d.forwards, id)
	}
	d.mu.Unlock()
	for _, actor := range actors {
		if actor.stop != nil {
			actor.stop()
		}
		if actor.fwd != nil {
			_ = actor.fwd.Close()
		}
		if actor.lease != nil {
			_ = actor.lease.Release()
		}
	}
	return true
}

// markCapabilityRestored returns true once per loss->restore transition.
func (d *dataPlane) markCapabilityRestored() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.capabilityReady {
		return false
	}
	d.capabilityReady = true
	return true
}

// stop implements reconcile.StopHook: it stops one forward's actor.
func (d *dataPlane) stop(ctx context.Context, forwardID string) error {
	d.mu.Lock()
	actor, ok := d.forwards[forwardID]
	if ok {
		delete(d.forwards, forwardID)
	}
	d.mu.Unlock()
	if !ok {
		return nil
	}
	if actor.stop != nil {
		actor.stop()
	}
	if actor.fwd != nil {
		_ = actor.fwd.Close()
	}
	if actor.lease != nil {
		return actor.lease.Release()
	}
	return nil
}

// recover reopens a listener for every durably applied PRESENT forward
// (restart path, Story 6). The received desired snapshot carries the spec
// (target etc.); the durable applied record carries the actual bind tuple.
func (d *dataPlane) recover(ctx context.Context) error {
	desired, ok, err := d.cfg.Store.LoadReceivedDesired()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	states, err := d.cfg.Store.ListAppliedStates()
	if err != nil {
		return err
	}
	specs := make(map[string]protocol.ForwardSpec, len(desired.Forwards))
	for _, spec := range desired.Forwards {
		if spec.Presence == protocol.PresencePresent {
			specs[spec.ForwardID] = spec
		}
	}
	for _, st := range states {
		spec, ok := specs[st.ForwardID]
		if !ok {
			continue
		}
		d.mu.Lock()
		_, exists := d.forwards[st.ForwardID]
		d.mu.Unlock()
		if exists {
			continue
		}
		if err := d.reopen(ctx, spec, st); err != nil {
			return err
		}
	}
	return nil
}

// reopen restores one forward's actor on the durable bind tuple.
func (d *dataPlane) reopen(ctx context.Context, spec protocol.ForwardSpec, st protocol.AppliedForwardState) error {
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
	lease, err := d.registry.Acquire(ctx, spec.ForwardID, traversal.TupleKey{
		Address:  sel.Source.String(),
		Port:     port,
		Family:   "ipv4",
		Protocol: "tcp",
	})
	if err != nil {
		return err
	}
	gate := reconcile.NewProbeGate(lease.Listener, d.cfg.ProbeMgr, reconcile.ProbeGateOptions{
		ForwardID:   spec.ForwardID,
		ReadTimeout: 2 * time.Second,
	})
	backend, err := forward.NewBackend(spec.Target)
	if err != nil {
		lease.Release()
		return err
	}
	fwd, err := tcp.New(gate, tcp.Options{Backend: backend, DialTimeout: 5 * time.Second})
	if err != nil {
		lease.Release()
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	go fwd.Run(runCtx)
	d.mu.Lock()
	if _, exists := d.forwards[spec.ForwardID]; exists {
		d.mu.Unlock()
		cancel()
		_ = fwd.Close()
		_ = lease.Release()
		return nil
	}
	d.forwards[spec.ForwardID] = &forwardActor{lease: lease, fwd: fwd, backend: backend, stop: cancel}
	d.mu.Unlock()
	if d.cfg.OnApplied != nil {
		d.cfg.OnApplied(spec, appliedState(spec, lease, d.cfg.Clock))
	}
	return nil
}

func (d *dataPlane) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, actor := range d.forwards {
		if actor.stop != nil {
			actor.stop()
		}
		if actor.fwd != nil {
			_ = actor.fwd.Close()
		}
		if actor.lease != nil {
			_ = actor.lease.Release()
		}
		delete(d.forwards, id)
	}
}

func appliedState(spec protocol.ForwardSpec, lease *traversal.Lease, clock func() time.Time) protocol.AppliedForwardState {
	return protocol.AppliedForwardState{
		ForwardID:       spec.ForwardID,
		SpecRevision:    spec.DesiredRevision,
		DesiredRevision: spec.DesiredRevision,
		ActualBindHost:  lease.Actual.Address,
		ActualBindPort:  lease.Actual.Port,
		Strategy:        string(spec.Strategy),
		LayerVersion:    1,
		AppliedAtUnix:   clock().Unix(),
	}
}
