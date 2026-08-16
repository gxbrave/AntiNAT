package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT/internal/controller"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/forward"
	tcpforward "github.com/gxbrave/AntiNAT/internal/forward/tcp"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

type mutableRouteTable struct {
	mu         sync.RWMutex
	gateway    netip.Addr
	iface      string
	hasDefault bool
	addrs      []traversal.IPv4Address
}

func (m *mutableRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gateway, m.iface, m.hasDefault, nil
}

func (m *mutableRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]traversal.IPv4Address(nil), m.addrs...), nil
}

// startTestController composes a controller app on an ephemeral port and
// returns it (with store access via app.Store()).
func startTestController(t *testing.T) *controller.App {
	t.Helper()
	app, err := controller.New(controller.Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("controller New: %v", err)
	}
	if err := app.Start(); err != nil {
		t.Fatalf("controller Start: %v", err)
	}
	t.Cleanup(func() { app.Shutdown(context.Background()) })
	return app
}

func TestAgentNewEnrollsAndConnects(t *testing.T) {
	ctrl := startTestController(t)
	if err := ctrl.Store().CreateNode(store.Node{ID: "n1", Name: "node-n1"}); err != nil {
		t.Fatalf("create node: %v", err)
	}
	token, err := ctrl.Store().CreateEnrollmentToken("n1", 3600)
	if err != nil {
		t.Fatalf("enrollment token: %v", err)
	}

	app, err := New(Config{
		StateDir:            t.TempDir(),
		Endpoint:            "http://" + ctrl.Addr(),
		NodeID:              "n1",
		Token:               token,
		ControllerPublicKey: ctrl.Hub().ControllerPublicKey(),
		Heartbeat:           50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := app.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !app.Ready() {
		t.Fatal("agent not ready after Start")
	}
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if app.Ready() {
		t.Fatal("agent still ready after Shutdown")
	}
	// A second Shutdown is idempotent.
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestOnForwardAppliedRotatesLiveActivationIdentity(t *testing.T) {
	a := &App{dp: &dataPlane{}, activations: make(map[string]*reconcile.Activation)}
	spec := protocol.ForwardSpec{ForwardID: "forward-rotate", DesiredRevision: 1}
	a.onForwardApplied(spec, protocol.AppliedForwardState{ForwardID: spec.ForwardID, SpecRevision: 1})
	first := a.activation(spec.ForwardID)
	if first == nil {
		t.Fatal("initial activation was not created")
	}
	firstID := first.ActivationID()
	secondSpec := spec
	secondSpec.DesiredRevision = 2
	a.onForwardApplied(secondSpec, protocol.AppliedForwardState{ForwardID: spec.ForwardID, SpecRevision: 2})
	second := a.activation(spec.ForwardID)
	want := protocol.ActivationID(spec.ForwardID, 2)
	if second.ActivationID() == firstID || second.ActivationID() != hex.EncodeToString(want[:]) {
		t.Fatalf("rotated activation id = %q, first = %q, want %x", second.ActivationID(), firstID, want)
	}
	if second.Generation() != 2 {
		t.Fatalf("rotated activation generation = %d, want 2", second.Generation())
	}
}

func TestOnForwardAppliedRollsBackLiveActivationIdentity(t *testing.T) {
	a := &App{dp: &dataPlane{}, activations: make(map[string]*reconcile.Activation)}
	forwardID := "forward-rollback"
	a.onForwardApplied(protocol.ForwardSpec{ForwardID: forwardID}, protocol.AppliedForwardState{ForwardID: forwardID, SpecRevision: 1})
	a.onForwardApplied(protocol.ForwardSpec{ForwardID: forwardID}, protocol.AppliedForwardState{ForwardID: forwardID, SpecRevision: 2})
	a.onForwardApplied(protocol.ForwardSpec{ForwardID: forwardID}, protocol.AppliedForwardState{ForwardID: forwardID, SpecRevision: 1})
	act := a.activation(forwardID)
	want := protocol.ActivationID(forwardID, 1)
	if act == nil || act.Generation() != 1 || act.ActivationID() != hex.EncodeToString(want[:]) {
		t.Fatalf("rollback activation = %+v, want generation 1 and activation %x", act, want)
	}
}

type blockingShutdownClient struct {
	unblock chan struct{}
}

func (c *blockingShutdownClient) Connect(context.Context) error                     { return nil }
func (c *blockingShutdownClient) SendMessage(context.Context, string, []byte) error { return nil }
func (c *blockingShutdownClient) Shutdown()                                         {}
func (c *blockingShutdownClient) Wait()                                             { <-c.unblock }

func TestShutdownHonorsContextWhileWaitingForControlDrain(t *testing.T) {
	client := &blockingShutdownClient{unblock: make(chan struct{})}
	a := &App{client: client}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := a.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want context deadline", err)
	}
	close(client.unblock)
}

func TestPrepareActivationRecoveryUnverifiesPersistedSnapshot(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	states := protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
		WanReachabilityState: "OPEN_FROM_VANTAGE", ReturnPathState: "VERIFIED",
		PublicationState: "PUBLISHED_VERIFIED", KeepaliveState: "HEALTHY", TargetHealthState: "PASS", DataPlaneState: "READY",
	}
	if err := st.SaveActivationSnapshot(localstate.ActivationSnapshot{
		ForwardID: "fwd-restart", Activation: "act-restart", Generation: 1, States: states,
	}); err != nil {
		t.Fatal(err)
	}
	a := &App{store: st}
	if err := a.prepareActivationRecovery(); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.LoadActivationSnapshot("fwd-restart")
	if err != nil || !ok {
		t.Fatalf("recovered snapshot ok=%v err=%v", ok, err)
	}
	if got.States.PublicationState != "PUBLISHED_UNVERIFIED" || got.States.WanReachabilityState != "NOT_TESTED" || got.States.ReturnPathState != "NOT_TESTED" {
		t.Fatalf("recovered states = %+v, want unverified/not-tested", got.States)
	}
}

func TestDataPlaneApplyDoesNotDeadlockActivationCallback(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })

	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	registry := traversal.NewPortRegistry()
	lease, err := registry.Acquire(context.Background(), "deadlock-test", traversal.TupleKey{
		Address: "127.0.0.1", Family: "ipv4", Protocol: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Release() })
	backend, err := forward.NewBackend(target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	d := newDataPlane(dataPlaneConfig{Store: st, Clock: time.Now})
	d.forwards["forward-deadlock-test"] = &forwardActor{lease: lease, backend: backend}
	a := &App{dp: d, activations: make(map[string]*reconcile.Activation)}
	d.cfg.OnApplied = a.onForwardApplied

	spec := protocol.ForwardSpec{
		ForwardID:       "forward-deadlock-test",
		Name:            "deadlock-test",
		Protocol:        protocol.ProtocolTCP,
		Target:          target.Addr().String(),
		Strategy:        protocol.StrategyDirectV4,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	done := make(chan error, 1)
	go func() {
		_, err := d.apply(context.Background(), spec)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("data-plane apply deadlocked while updating activation state")
	}
}

func TestAgentStartupFailureRollsBack(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	app, err := New(Config{
		StateDir:            filepath.Join(blocker, "sub"),
		Endpoint:            "http://127.0.0.1:1",
		NodeID:              "n1",
		Token:               "x",
		ControllerPublicKey: make([]byte, ed25519.PublicKeySize),
	})
	if err == nil {
		if app != nil {
			_ = app.Shutdown(context.Background())
		}
		t.Fatal("New succeeded with an unwritable state dir")
	}
}

// RED R7-2: an accepted controller-side probe outcome must be joined into the
// current activation, rather than leaving the agent in PROBING forever.
func TestProbeOutcomeCommandJoinsActivationState(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d := newDataPlane(dataPlaneConfig{Store: st, Clock: time.Now})
	act := reconcile.NewActivation("fwd-outcome", "act-outcome", 1)
	if err := act.StartProbe(1); err != nil {
		t.Fatal(err)
	}
	a := &App{store: st, dp: d, activations: map[string]*reconcile.Activation{
		"fwd-outcome": act,
	}}
	payload, err := json.Marshal(map[string]any{
		"forward_id": "fwd-outcome", "activation": "act-outcome",
		"generation": 1, "outcome": string(protocol.OutcomeOpenFromVantage),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.handleCommand(context.Background(), control.Operation{
		MessageType: "probe_outcome", Payload: payload,
	}); err != nil {
		t.Fatalf("probe outcome command: %v", err)
	}
	snap := act.Snapshot()
	if snap.WanReachabilityState != string(protocol.OutcomeOpenFromVantage) ||
		snap.PublicationState != "PUBLISHED_VERIFIED" {
		t.Fatalf("activation after outcome = %+v", snap)
	}
}

// TestMonitorLivenessRevokesOnRouteFingerprintChange covers the lifecycle
// boundary where a still-DIRECT_V4_READY route changes its gateway. Capability
// code alone remains READY, but the route/interface evidence fingerprint must
// revoke the current data-plane publication.
func TestMonitorLivenessRevokesOnRouteFingerprintChange(t *testing.T) {
	routes := &mutableRouteTable{
		gateway:    netip.MustParseAddr("192.168.1.1"),
		iface:      "eth0",
		hasDefault: true,
		addrs:      []traversal.IPv4Address{{Interface: "eth0", Addr: netip.MustParseAddr("8.8.8.8")}},
	}
	d := newDataPlane(dataPlaneConfig{RouteTable: routes, Clock: time.Now})
	if !d.capabilityReady {
		t.Fatal("initial route table should be capability-ready")
	}
	a := &App{
		cfg:         Config{RouteTable: routes, LivenessInterval: 5 * time.Millisecond},
		dp:          d,
		activations: make(map[string]*reconcile.Activation),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.monitorLiveness(ctx)

	routes.mu.Lock()
	routes.gateway = netip.MustParseAddr("192.168.1.254")
	routes.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		lost := !d.capabilityReady
		d.mu.Unlock()
		if lost {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("gateway change did not revoke capability readiness")
}

type closeErrorListener struct {
	net.Listener
	err error
}

func (l *closeErrorListener) Close() error {
	_ = l.Listener.Close()
	return l.err
}

func TestDataPlaneStopSurfacesAndRetainsForwardCloseError(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("listener close failed")
	listener := &closeErrorListener{Listener: base, err: closeErr}
	backend, err := forward.NewBackend("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	fwd, err := tcpforward.New(listener, tcpforward.Options{Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	d := newDataPlane(dataPlaneConfig{})
	d.forwards["stop-error"] = &forwardActor{fwd: fwd}
	if err := d.stop(context.Background(), "stop-error"); !errors.Is(err, closeErr) {
		t.Fatalf("data-plane stop error = %v, want listener close error", err)
	}
	if _, ok := d.forwards["stop-error"]; !ok {
		t.Fatal("failed forward close was removed before durable retry")
	}
}
