package hook_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

// P3-2: internal/hook previously had ZERO goroutines in its tests, so
// `-race -count=10` could not exercise the concurrency surfaces this package
// claims to support. These tests are deterministic: no sleeps for correctness —
// termination comes from channels, WaitGroups and bounded counters.

// RED repair P3-2 (a): N goroutines race ReserveSecretSignature near
// exhaustion against a durable budget of K < N. SQLite's writer serialization
// must allow EXACTLY K reservations; the total issued counter must never exceed
// K. The broker.Sign path (decrypt + endpoint re-derivation + allowlist +
// reserve) is what races, so this exercises the full signing pipeline.
func TestConcurrentReserveSecretSignatureNearExhaustion(t *testing.T) {
	hs, ks, broker := newBroker(t)
	d := mustDefinition(t, hs, "web", "https://dns.aliyuncs.com/")
	mustCreateSecret(t, hs, ks, "access-key-1", "HMAC-SHA256", "secret-value")
	const budget = int64(4)
	const workers = 32
	mustEnableSecret(t, hs, d.ID, "access-key-1", budget)

	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			intent := baseIntent(d)
			intent.Body = []byte(fmt.Sprintf(`{"worker":%d}`, i))
			_, _, err := broker.Sign(context.Background(), intent)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	ok := 0
	for err := range results {
		if err == nil {
			ok++
			continue
		}
		if !errors.Is(err, hook.ErrSignatureBudgetExhausted) {
			t.Fatalf("unexpected concurrent sign error: %v", err)
		}
	}
	if ok != int(budget) {
		t.Fatalf("concurrent signs succeeded = %d, want exactly %d", ok, budget)
	}
	issued, gotBudget, err := hs.SignatureUsage("access-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if issued != budget || gotBudget != budget {
		t.Fatalf("signature usage = %d/%d, want %d/%d (total issued never exceeds the budget)", issued, gotBudget, budget, budget)
	}
}

// RED repair P3-2 (b): the dispatcher pump runs CONCURRENTLY with delivery
// retries under -race. Four pumper goroutines call PumpOnce in a loop while a
// retrier requeues FAILED deliveries; the sender always fails so deliveries
// cycle PENDING->FAILED->retried->PENDING, exercising ClaimDue/MarkFailed/
// RetryDelivery from many goroutines at once. Termination is deterministic:
// the retrier stops after successfully retrying every delivery and closes the
// stop channel; the pumpers exit on the channel. No delivery is ever lost.
func TestConcurrentDispatcherPumpAndRetry(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.invalid/hook")
	sender := &fakeSender{err: errors.New("transient connection reset")}
	dispatcher := hook.NewDispatcher(hs, sender, passthroughPreparer{}, hook.DispatcherConfig{Batch: 8})

	const deliveries = 16
	for i := 0; i < deliveries; i++ {
		mustEnqueue(t, hs, hook.Event{
			HookID: d.ID, EventID: fmt.Sprintf("evt-%d", i),
			Policy: hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxAttempts: 100},
		})
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					dispatcher.PumpOnce()
				}
			}
		}()
	}

	wg.Add(1)
	var retried int
	go func() {
		defer wg.Done()
		for retried < deliveries {
			all, err := hs.ListDeliveries(100)
			if err != nil {
				continue // transient store contention while the pumpers write; not a correctness sleep
			}
			for _, dl := range all {
				if dl.State == hook.DeliveryFailed {
					if _, err := hs.RetryDelivery(dl.ID); err == nil {
						retried++
					}
				}
			}
		}
		close(stop)
	}()

	wg.Wait()
	if retried < deliveries {
		t.Fatalf("retrier completed %d retries, want >= %d (every delivery transiently FAILED)", retried, deliveries)
	}
	all, err := hs.ListDeliveries(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != deliveries {
		t.Fatalf("deliveries after concurrent pump/retry = %d, want %d (no loss)", len(all), deliveries)
	}
}

// RED repair P3-3: RuntimeRunner.Capability() previously read/wrote the lazy
// probe state (probed/probedDone) with NO lock — safe only because the
// dispatcher is single-goroutine today. This test hammers Capability() from
// many goroutines while others call SetUnsupported() (a write), exercising the
// former read/write race under -race. The probe uses a deliberately
// non-existent child path so the lazy probe fails closed quickly instead of
// spawning a real child; the point is the probe-state access pattern, not the
// gate outcome.
func TestConcurrentCapabilityProbeAndToggle(t *testing.T) {
	r := hook.NewRuntimeRunner("definitely-not-a-real-runner-binary", hook.DefaultLimits())
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]int{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				cap := r.Capability()
				mu.Lock()
				seen[cap]++
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.SetUnsupported()
				_ = r.Capability()
			}
		}()
	}
	wg.Wait()
	if len(seen) == 0 {
		t.Fatal("no capability observations recorded")
	}
	if c := r.Capability(); c != "unsupported" {
		t.Fatalf("final capability = %q, want unsupported", c)
	}
}

// RED repair P3-2 (c): concurrent bind READ/WRITE — multiple goroutines issue
// idempotent BindSecretToHook while others call IsSecretBoundToHook. The store
// must serialize them and settle on bound=true with no race and no lost write.
func TestConcurrentBindReadWrite(t *testing.T) {
	hs, ks, _ := newBroker(t)
	d := mustDefinition(t, hs, "web", "https://example.invalid/hook")
	mustCreateSecret(t, hs, ks, "access-key-1", "HMAC-SHA256", "secret-value")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = hs.BindSecretToHook(d.ID, "access-key-1") // idempotent INSERT ... DO NOTHING
				_, _ = hs.IsSecretBoundToHook(d.ID, "access-key-1")
			}
		}()
	}
	wg.Wait()
	bound, err := hs.IsSecretBoundToHook(d.ID, "access-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bound {
		t.Fatal("secret not bound after concurrent idempotent binds")
	}
}
