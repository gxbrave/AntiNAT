package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestControllerShutdownCanRetryAfterWatcherDeadline(t *testing.T) {
	app, err := New(Config{
		StorePath: filepath.Join(t.TempDir(), "controller.db"),
		KeyDir: filepath.Join(t.TempDir(), "keys"),
		Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	app.watchWG.Add(1)
	go func() {
		<-release
		app.watchWG.Done()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := app.Shutdown(ctx); err == nil {
		t.Fatal("first Shutdown succeeded while watcher was blocked")
	}
	close(release)
	if err := app.Shutdown(context.Background()); err != nil {
		t.Fatalf("retry Shutdown: %v", err)
	}
	if err := app.Store().CreateNode(store.Node{ID: "closed", Name: "closed"}); err == nil {
		t.Fatal("store remained usable after retry Shutdown")
	}
}
