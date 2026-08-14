package agent

import (
	"context"
	"crypto/ed25519"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT/internal/controller"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/forward"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

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
