package controller

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// TestStartupFailureRollsBackReadiness is Story 5 RED: when the HTTP server
// cannot bind (port already taken), the app must fail startup AND close the
// resources it already opened (store), leaving readiness false.
func TestStartupFailureRollsBackReadiness(t *testing.T) {
	// Occupy a port so the app's bind fails after store/keyring were opened.
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	addr := blocker.Addr().String()

	app, err := New(Config{
		ListenAddress: addr,
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Start(); err == nil {
		t.Fatal("Start succeeded on an occupied address, want failure")
	}
	if app.Ready() {
		t.Fatal("app reports ready after failed startup")
	}
	// The store opened during New must have been rolled back (closed).
	if _, err := app.Store().GetNode("nope"); err == nil {
		t.Fatal("store still usable after rolled-back startup, want closed")
	}
	// Double shutdown after rollback is safe.
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after rollback: %v", err)
	}
}

// TestShutdownClosesResourcesInOrder is Story 5 RED: Shutdown must stop the
// HTTP server before closing the store, and a second Shutdown is idempotent.
func TestShutdownClosesResourcesInOrder(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !app.Ready() {
		t.Fatal("app not ready after successful startup")
	}
	addr := app.Addr()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if app.Ready() {
		t.Fatal("app still ready after Shutdown")
	}
	// HTTP server must be gone (first in close order).
	conn, err := net.DialTimeout("tcp4", addr, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("HTTP listener still accepting after Shutdown")
	}
	// Store must be closed (last in close order).
	if _, err := app.Store().GetNode("nope"); err == nil {
		t.Fatal("store still usable after Shutdown, want closed")
	}
	// Order: HTTP server closed before store.
	order := app.CloseOrder()
	if len(order) != 2 || order[0] != "http" || order[1] != "store" {
		t.Fatalf("close order = %v, want [http store]", order)
	}
	// Idempotent second Shutdown.
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// TestStartupHealthRoutes is a smoke check: the composed app serves the
// minimal admin API (healthz/readyz) and the agent hub surface on one
// listener.
func TestStartupHealthRoutes(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer app.Shutdown(context.Background())

	resp, err := http.Get("http://" + app.Addr() + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", resp.StatusCode)
	}
	resp, err = http.Get("http://" + app.Addr() + "/readyz")
	if err != nil {
		t.Fatalf("readyz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz = %d, want 200", resp.StatusCode)
	}
}
