package controller

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestControllerShutdownCanRetryAfterWatcherDeadline(t *testing.T) {
	app, err := New(Config{
		StorePath: filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:    filepath.Join(t.TempDir(), "keys"),
		Clock:     time.Now,
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

func TestControllerShutdownConcurrentCallsAreSerialized(t *testing.T) {
	app, err := New(Config{
		StorePath: filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:    filepath.Join(t.TempDir(), "keys"),
		Clock:     time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- app.Shutdown(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Shutdown: %v", err)
		}
	}
}
