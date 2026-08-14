package agent

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
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
