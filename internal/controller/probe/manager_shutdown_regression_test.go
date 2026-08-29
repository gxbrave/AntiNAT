package probe

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

type cancelAwareRoundTripper struct {
	mu       sync.Mutex
	requests int
	entered  chan struct{}
}

func (t *cancelAwareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests++
	requestNumber := t.requests
	if requestNumber == 1 {
		close(t.entered)
	}
	t.mu.Unlock()
	if requestNumber == 1 {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
		Request:       req,
	}, nil
}

func (t *cancelAwareRoundTripper) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.requests
}

// TestManagerCloseContextReturnsDeadlineWhileFinalizerDrains exercises a
// non-cooperative RoundTripper. CloseContext must return the caller deadline,
// but the manager-owned finalizer must retain active/round ownership and keep
// the store open until the transport eventually returns.
func TestManagerCloseContextReturnsDeadlineWhileFinalizerDrains(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	transport := &blockingRoundTripper{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	env.manager.client = &http.Client{Transport: transport}
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider request did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := env.manager.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext error = %v, want deadline exceeded", err)
	}
	if got, err := env.store.GetProbeOperation(op.ID); err != nil || got.Status != "IN_FLIGHT" {
		t.Fatalf("in-flight operation during bounded close = %+v (err %v), want ownership preserved", got, err)
	}
	transport.releaseOnce()
	joinDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(joinDeadline) {
		if err := env.manager.CloseContext(context.Background()); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("manager finalizer did not finish after provider returned")
}

type blockingRoundTripper struct {
	mu       sync.Mutex
	entered  chan struct{}
	release  chan struct{}
	released bool
}

func (t *blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	select {
	case <-t.entered:
	default:
		close(t.entered)
	}
	release := t.release
	t.mu.Unlock()
	<-release
	return nil, errors.New("blocking test transport released")
}

func (t *blockingRoundTripper) releaseOnce() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.released {
		t.released = true
		close(t.release)
	}
}

// TestManagerCloseLeavesCancelledProviderRoundRecoverable proves controller
// shutdown cancellation is not provider evidence. The interrupted request
// leaves IN_FLIGHT, and a fresh manager requeues it and admits exactly one
// provider retry.
func TestManagerCloseLeavesCancelledProviderRoundRecoverable(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	transport := &cancelAwareRoundTripper{entered: make(chan struct{})}

	env.manager.client = &http.Client{Transport: transport}
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.manager.Start(context.Background()); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatalf("admit probe_armed: %v", err)
	}
	select {
	case <-transport.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider request did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- env.manager.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close manager: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("manager Close did not cancel the provider request")
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("cancelled provider operation status = %q, want IN_FLIGHT", got.Status)
	}

	restarted, err := NewManager(ManagerConfig{
		Store:         env.store,
		Keyring:       env.keyring,
		Clock:         time.Now,
		HTTPClient:    &http.Client{Transport: transport},
		NodePublicKey: func(string) (ed25519.PublicKey, bool) { return env.nodePub, true },
	})
	if err != nil {
		t.Fatalf("restart manager: %v", err)
	}
	if err := restarted.recoverOperations(); err != nil {
		t.Fatalf("recover cancelled provider operation: %v", err)
	}
	defer restarted.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && transport.count() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("provider requests after restart = %d, want exactly 2", got)
	}
	// A second recovery while the retry is active must not admit a duplicate.
	if err := restarted.recoverOperations(); err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := transport.count(); got != 2 {
		t.Fatalf("duplicate provider retry after restart = %d, want 2", got)
	}
}
