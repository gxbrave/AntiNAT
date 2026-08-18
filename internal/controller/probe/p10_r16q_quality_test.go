package probe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// The lifecycle lock must cover the whole Close wait. Otherwise Start can
// install a fresh sweeper after Close has cancelled the old one, leaving Close
// waiting on a WaitGroup that the new sweeper never joins.
func TestR16QManagerCloseSerializesConcurrentStart(t *testing.T) {
	env := newTestEnv(t, false)
	mgr := env.manager
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Keep Close in its join phase while a concurrent Start is attempted. This
	// is a test-only waiter; production work is already fenced by m.mu.
	mgr.mu.Lock()
	mgr.workWG.Add(1)
	mgr.mu.Unlock()

	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		closing := mgr.cancel == nil && mgr.closed
		mgr.mu.Unlock()
		if closing {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mgr.mu.Lock()
	closing := mgr.cancel == nil && mgr.closed
	mgr.mu.Unlock()
	if !closing {
		t.Fatal("Close did not reach its cancellation/join phase")
	}

	startDone := make(chan error, 1)
	startCtx, cancelStart := context.WithCancel(context.Background())
	defer cancelStart()
	go func() { startDone <- mgr.Start(startCtx) }()

	select {
	case err := <-startDone:
		// The old implementation returns here and leaks a new sweeper into the
		// in-progress Close. Finish cleanup below so the test never strand a
		// goroutine, then report the lifecycle violation.
		if err == nil {
			cancelStart()
		}
		mgr.workWG.Done()
		if closeErr := <-closeDone; closeErr != nil {
			t.Fatalf("Close: %v", closeErr)
		}
		if err == nil {
			_ = mgr.Close()
		}
		t.Fatalf("concurrent Start returned before Close completed: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: Start is serialized behind Close.
	}

	mgr.workWG.Done()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-startDone; err != nil {
		t.Fatalf("Start after Close: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}
}

// A revision advance may retain the same activation identifier. Arm must not
// reuse the runtime mirror observed at the previous generation.
func TestR16QArmRejectsSameActivationAfterForwardRevisionAdvance(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	if err := env.store.CASForwardActivation("f1", 1, "act-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := env.manager.Arm(context.Background(), "n1", "f1", "act-1", "198.51.100.7:8080"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Arm after same-activation generation advance = %v, want invalidated runtime mirror", err)
	}
	if _, err := env.store.GetForwardRuntimeStatus("f1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale runtime mirror survived generation advance: %v", err)
	}
	if live, err := env.store.CountLiveProbeOperations(); err != nil || live != 0 {
		t.Fatalf("stale-generation Arm created %d live operations (err %v)", live, err)
	}
}
