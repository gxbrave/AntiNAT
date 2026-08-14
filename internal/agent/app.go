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

	closeMu sync.Mutex
	closed  bool
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
	})
	if err != nil {
		return rollback(fmt.Errorf("agent: control client: %w", err))
	}
	a.client = client
	return a, nil
}

// Start connects the control channel and marks the app ready once the
// session handshake completes. It blocks until the first connect succeeds
// or ctx is done; later session drops are handled by the client's loops.
func (a *App) Start(ctx context.Context) error {
	if err := a.client.Connect(ctx); err != nil {
		a.client.Close()
		return fmt.Errorf("agent: control connect: %w", err)
	}
	// Restart recovery: reopen listeners for durably applied forwards
	// (Story 6: restart restores the listener, initially UNVERIFIED).
	if err := a.dp.recover(ctx); err != nil {
		a.client.Close()
		return fmt.Errorf("agent: data plane recovery: %w", err)
	}
	a.ready.Store(true)
	return nil
}

// Ready reports whether the control session is established.
func (a *App) Ready() bool { return a.ready.Load() }

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
	defer a.dp.mu.Unlock()
	act, ok := a.activations[applied.ForwardID]
	if !ok {
		aid := protocol.ActivationID(applied.ForwardID, applied.SpecRevision)
		act = reconcile.NewActivation(applied.ForwardID, hex.EncodeToString(aid[:]), applied.SpecRevision)
		a.activations[applied.ForwardID] = act
		return
	}
	act.AdvanceGeneration(applied.SpecRevision)
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
	if a.client != nil {
		a.client.Close()
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
	cfg      dataPlaneConfig
	mu       sync.Mutex
	forwards map[string]*forwardActor
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
	return &dataPlane{cfg: cfg, forwards: make(map[string]*forwardActor)}
}

// apply implements reconcile.ApplyHook: it opens (or hot-updates) one
// direct-v4 forward and returns the durable applied state.
func (d *dataPlane) apply(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if actor, ok := d.forwards[spec.ForwardID]; ok {
		// Hot update: the listener stays, the backend target swaps
		// atomically; new sessions resolve the new snapshot at accept time.
		if err := actor.backend.Update(spec.Target); err != nil {
			return protocol.AppliedForwardState{}, err
		}
		st := appliedState(spec, actor.lease, d.cfg.Clock)
		if d.cfg.OnApplied != nil {
			d.cfg.OnApplied(spec, st)
		}
		return st, nil
	}

	if spec.Strategy != protocol.StrategyDirectV4 {
		return protocol.AppliedForwardState{}, fmt.Errorf("agent: strategy %q not supported by the M1 data plane", spec.Strategy)
	}
	sel, capability, err := traversal.Assess(d.cfg.RouteTable)
	if err != nil || capability != traversal.CapabilityDirectV4Ready {
		return protocol.AppliedForwardState{}, traversal.ErrNoGlobalV4Source
	}
	registry := traversal.NewPortRegistry()
	lease, err := registry.Acquire(ctx, spec.ForwardID, traversal.TupleKey{
		Address:  sel.Source.String(),
		Port:     spec.RequestedLocalPort,
		Family:   "ipv4",
		Protocol: "tcp",
	})
	if err != nil {
		return protocol.AppliedForwardState{}, err
	}
	gate := reconcile.NewProbeGate(lease.Listener, d.cfg.ProbeMgr, reconcile.ProbeGateOptions{
		ForwardID:   spec.ForwardID,
		ReadTimeout: 2 * time.Second,
	})
	backend, err := forward.NewBackend(spec.Target)
	if err != nil {
		lease.Release()
		return protocol.AppliedForwardState{}, err
	}
	fwd, err := tcp.New(gate, tcp.Options{Backend: backend, DialTimeout: 5 * time.Second})
	if err != nil {
		lease.Release()
		return protocol.AppliedForwardState{}, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	go fwd.Run(runCtx)
	d.forwards[spec.ForwardID] = &forwardActor{lease: lease, fwd: fwd, backend: backend, stop: cancel}
	st := appliedState(spec, lease, d.cfg.Clock)
	if d.cfg.OnApplied != nil {
		d.cfg.OnApplied(spec, st)
	}
	return st, nil
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
	actor.stop()
	_ = actor.fwd.Close()
	return actor.lease.Release()
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
		if _, exists := d.forwards[st.ForwardID]; exists {
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
	registry := traversal.NewPortRegistry()
	lease, err := registry.Acquire(ctx, spec.ForwardID, traversal.TupleKey{
		Address:  st.ActualBindHost,
		Port:     st.ActualBindPort,
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
	d.forwards[spec.ForwardID] = &forwardActor{lease: lease, fwd: fwd, backend: backend, stop: cancel}
	if d.cfg.OnApplied != nil {
		d.cfg.OnApplied(spec, appliedState(spec, lease, d.cfg.Clock))
	}
	return nil
}

func (d *dataPlane) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, actor := range d.forwards {
		actor.stop()
		_ = actor.fwd.Close()
		_ = actor.lease.Release()
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
