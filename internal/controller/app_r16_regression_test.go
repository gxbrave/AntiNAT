package controller

import (
	"context"
	"path/filepath"
	"testing"
)

// R16 RED: Shutdown-before-Start must move the app to a terminal state; a
// later Start must not bind a listener or launch workers on closed resources.
func TestR16ControllerShutdownBeforeStartIsTerminal(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown before start: %v", err)
	}
	if err := app.Start(); err == nil {
		t.Fatal("Start after terminal Shutdown succeeded")
	}
	if app.Ready() {
		t.Fatal("app became ready after terminal Shutdown")
	}
}

// R16 RED: Start is a single-shot lifecycle transition; concurrent callers may
// not overwrite the listener/server fields or launch duplicate watchers.
func TestR16ControllerStartIsSingleShot(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown(context.Background())
	if err := app.Start(); err == nil {
		t.Fatal("second Start succeeded")
	}
}

func TestR16ControllerStartShutdownRaceEndsClosed(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	startDone := make(chan error, 1)
	shutdownDone := make(chan error, 1)
	go func() { startDone <- app.Start() }()
	go func() { shutdownDone <- app.Shutdown(context.Background()) }()
	if err := <-startDone; err != nil {
		// Shutdown is allowed to win the serialized NEW->CLOSING race.
		if err := <-shutdownDone; err != nil {
			t.Fatalf("shutdown after rejected start: %v", err)
		}
	} else if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown after successful start: %v", err)
	}
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("final idempotent shutdown: %v", err)
	}
	if app.Ready() {
		t.Fatal("app remained ready after Start/Shutdown race")
	}
	if err := app.Start(); err == nil {
		t.Fatal("Start reopened app after race reached CLOSED")
	}
}
