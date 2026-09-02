package hook_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

type fakeSender struct {
	mu    sync.Mutex
	calls []*hook.SignedRequest
	err   error
	code  int
}

func (f *fakeSender) Send(ctx context.Context, req *hook.SignedRequest) (*hook.SendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, req)
	return &hook.SendResult{StatusCode: 200}, nil
}

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type passthroughPreparer struct{}

func (passthroughPreparer) Prepare(ctx context.Context, d hook.Delivery) (*hook.SignedRequest, error) {
	h := http.Header{}
	h.Set("X-Event-ID", d.EventID)
	h.Set("X-Delivery-ID", d.ID)
	return &hook.SignedRequest{
		Method:  "POST",
		URL:     "https://example.invalid/hook",
		Headers: h,
		Body:    []byte(d.PayloadJSON),
	}, nil
}

// RED P16 Story 1 (i): a single pump claims a PENDING delivery, prepares a
// request with the stable event/delivery ids, sends it, and marks it DELIVERED.
func TestDispatcherDeliversAndMarksDelivered(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.invalid/hook")
	evt := hook.Event{HookID: d.ID, EventID: "evt-1", Payload: []byte(`{"a":1}`)}
	mustEnqueue(t, hs, evt)
	sender := &fakeSender{}
	dispatcher := hook.NewDispatcher(hs, sender, passthroughPreparer{}, hook.DispatcherConfig{Batch: 16})
	if n := dispatcher.PumpOnce(); n != 1 {
		t.Fatalf("pump delivered %d, want 1", n)
	}
	if sender.count() != 1 {
		t.Fatalf("sender called %d times, want 1", sender.count())
	}
	req := sender.calls[0]
	if req.URL != "https://example.invalid/hook" || req.Method != "POST" || string(req.Body) != `{"a":1}` {
		t.Fatalf("unexpected prepared request: %+v", req)
	}
	if got := req.Headers.Get("X-Event-ID"); got != "evt-1" {
		t.Fatalf("X-Event-ID = %q, want evt-1 (duplicate-tolerant receivers)", got)
	}
	deliveries, _ := hs.ListDeliveries(10)
	if len(deliveries) != 1 || deliveries[0].State != hook.DeliveryDelivered {
		t.Fatalf("delivery not DELIVERED: %+v", deliveries)
	}
}

// RED P16 Story 1 (j): a failing sender records a transient FAILED state with
// a bounded backoff; after the attempt bound the delivery dead-letters.
func TestDispatcherFailureRetriesThenDLQs(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.invalid/hook")
	mustEnqueue(t, hs, hook.Event{
		HookID: d.ID, EventID: "evt-fail",
		Policy: hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxAttempts: 2},
	})
	sender := &fakeSender{err: errors.New("connection reset by peer")}
	dispatcher := hook.NewDispatcher(hs, sender, passthroughPreparer{}, hook.DispatcherConfig{Batch: 16})

	if n := dispatcher.PumpOnce(); n != 1 {
		t.Fatalf("first pump delivered %d", n)
	}
	all, _ := hs.ListDeliveries(10)
	if all[0].State != hook.DeliveryFailed {
		t.Fatalf("state = %q, want FAILED", all[0].State)
	}
	if all[0].LastError != "connection reset by peer" {
		t.Fatalf("last_error = %q", all[0].LastError)
	}
	// Second attempt: requeue + fail again -> DLQED.
	if n := dispatcher.PumpOnce(); n != 0 {
		t.Fatalf("second pump claimed %d (backoff not honored)", n)
	}
	// The bounded backoff moved next_attempt_at into the future; make it due and
	// pump again.
	hs.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	if n := dispatcher.PumpOnce(); n != 1 {
		t.Fatalf("third pump claimed %d", n)
	}
	all, _ = hs.ListDeliveries(10)
	if all[0].State != hook.DeliveryDLQed {
		t.Fatalf("terminal state = %q, want DLQED", all[0].State)
	}
}

// RED P16 Story 1 (k): markFailed scrubs a hostile newline-injected error so
// the durable last_error never contains control characters.
func TestScrubErrorRemovesControlCharacters(t *testing.T) {
	fake := errors.New("head\ninjected-secret: abc\r\nmore")
	scrubbed := hook.ScrubError(fake)
	if strings.ContainsAny(scrubbed, "\r\n") {
		t.Fatalf("scrub kept control characters: %q", scrubbed)
	}
	if len(scrubbed) > 256 {
		t.Fatalf("scrub did not bound length: %d", len(scrubbed))
	}
}

// RED P16 Story 1 (l): pumpOnce with a nil sender/preparer fails closed (0).
func TestDispatcherFailsClosedWithoutSender(t *testing.T) {
	hs := newTestHookStore(t)
	dispatcher := hook.NewDispatcher(hs, nil, passthroughPreparer{}, hook.DispatcherConfig{})
	if n := dispatcher.PumpOnce(); n != 0 {
		t.Fatalf("pump with nil sender = %d, want 0 (fail closed)", n)
	}
}
