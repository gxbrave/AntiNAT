package hook_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

// RED P16 Story 1 (a): a durable enqueue yields a stable delivery id and the
// stable event id is preserved; the delivery starts PENDING with the correct
// hook/kind/payload and an immediately-claimable next_attempt_at.
func TestEnqueueCreatesPendingStableDelivery(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	evt := hook.Event{
		HookID: d.ID, EventID: "evt-001", Kind: "forward_delete", NodeID: "node-1",
		Payload: []byte(`{"forward_id":"fwd-1"}`),
		Policy:  hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxAttempts: 4},
	}
	delivery := mustEnqueue(t, hs, evt)
	if delivery.ID == "" {
		t.Fatal("delivery id empty")
	}
	if delivery.EventID != "evt-001" || delivery.HookID != d.ID || delivery.Kind != "forward_delete" {
		t.Fatalf("delivery identity not preserved: %+v", delivery)
	}
	if delivery.State != hook.DeliveryPending {
		t.Fatalf("state = %q, want %q", delivery.State, hook.DeliveryPending)
	}
	if delivery.MaxAttempts != 4 {
		t.Fatalf("max_attempts = %d, want 4", delivery.MaxAttempts)
	}
	if delivery.PayloadJSON != `{"forward_id":"fwd-1"}` {
		t.Fatalf("payload = %q", delivery.PayloadJSON)
	}
	if delivery.NextAttemptAt > 1_700_000_000 {
		t.Fatalf("fresh delivery not immediately claimable: next_attempt_at=%d", delivery.NextAttemptAt)
	}
}

// RED P16 Story 1 (b): enqueuing the same (hook_id, event_id) twice is
// idempotent — the same delivery row is returned and no second row exists.
func TestEnqueueDuplicateEventIsIdempotent(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	evt := hook.Event{HookID: d.ID, EventID: "evt-dup", Payload: []byte(`{}`)}
	first := mustEnqueue(t, hs, evt)
	second := mustEnqueue(t, hs, evt)
	if first.ID != second.ID {
		t.Fatalf("duplicate enqueue created a new delivery: %s vs %s", first.ID, second.ID)
	}
	all, err := hs.ListDeliveries(10)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, dl := range all {
		if dl.EventID == "evt-dup" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate event created %d rows, want 1", count)
	}
}

// RED P16 Story 1 (c): a claimed delivery is IN_FLIGHT and completing it moves
// it to DELIVERED; a second claim does not resurrect it.
func TestClaimDeliversAndDoesNotResurrect(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	delivery := mustEnqueue(t, hs, hook.Event{HookID: d.ID, EventID: "evt-1", Payload: []byte(`{}`)})
	claimed, err := hs.ClaimDue(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ID != delivery.ID || claimed[0].State != hook.DeliveryInFlight {
		t.Fatalf("claim = %+v", claimed)
	}
	if err := hs.MarkDelivered(delivery.ID); err != nil {
		t.Fatal(err)
	}
	got, err := hs.GetDelivery(delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != hook.DeliveryDelivered {
		t.Fatalf("state = %q, want %q", got.State, hook.DeliveryDelivered)
	}
	again, err := hs.ClaimDue(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("delivered delivery was re-claimed: %+v", again)
	}
}

// RED P16 Story 1 (d): a failed delivery gets a bounded backoff (1..300s) and
// is retryable; at the attempt bound it is dead-lettered (DLQED), never
// silently lost.
func TestFailedDeliveryRetriesWithBoundedBackoffThenDLQ(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	delivery := mustEnqueue(t, hs, hook.Event{
		HookID: d.ID, EventID: "evt-retry",
		Policy: hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxAttempts: 3},
	})
	for attempt := 1; attempt <= 2; attempt++ {
		// Advance the clock past the bounded backoff so the retry is due.
		hs.SetClock(func() time.Time { return time.Unix(1_700_000_000+int64(attempt)*30, 0) })
		claimed, err := hs.ClaimDue(10)
		if err != nil {
			t.Fatal(err)
		}
		if len(claimed) != 1 {
			t.Fatalf("attempt %d: no delivery claimed", attempt)
		}
		if err := hs.MarkFailed(claimed[0].ID, "connection refused"); err != nil {
			t.Fatal(err)
		}
		got, _ := hs.GetDelivery(delivery.ID)
		if got.State != hook.DeliveryFailed {
			t.Fatalf("attempt %d: state = %q, want FAILED", attempt, got.State)
		}
		delay := got.NextAttemptAt - 1_700_000_000
		if delay < 1 || delay > 300 {
			t.Fatalf("attempt %d: backoff = %ds, want 1..300", attempt, delay)
		}
		if got.AttemptCount != attempt {
			t.Fatalf("attempt %d: attempt_count = %d", attempt, got.AttemptCount)
		}
	}
	hs.SetClock(func() time.Time { return time.Unix(1_700_000_000+120, 0) })
	claimed, err := hs.ClaimDue(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 {
		t.Fatalf("final attempt: no delivery claimed (next_attempt_at may have been in the future)")
	}
	if err := hs.MarkFailed(claimed[0].ID, "connection refused"); err != nil {
		t.Fatal(err)
	}
	got, err := hs.GetDelivery(delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != hook.DeliveryDLQed {
		t.Fatalf("final state = %q, want DLQED", got.State)
	}
}

// RED P16 Story 1 (e): the queue-full drop policy returns ErrQueueFull, never
// loses the event without a durable admin_events audit row, and leaves the
// backlog intact.
func TestQueueFullDropAudits(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	policy := hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDrop, MaxQueue: 1}
	mustEnqueue(t, hs, hook.Event{HookID: d.ID, EventID: "evt-a", Policy: policy})
	_, err := hs.EnqueueEvent(hook.Event{HookID: d.ID, EventID: "evt-b", Policy: policy})
	if !errors.Is(err, hook.ErrQueueFull) {
		t.Fatalf("drop policy err = %v, want ErrQueueFull", err)
	}
	events, err := hs.AdminEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	var audited bool
	for _, ev := range events {
		if ev == "HOOK_DELIVERY_DROPPED" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("drop was not durably audited (silent loss)")
	}
	// Backlog is still exactly the first event.
	all, _ := hs.ListDeliveries(10)
	if len(all) != 1 || all[0].EventID != "evt-a" {
		t.Fatalf("backlog changed after drop: %+v", all)
	}
}

// RED P16 Story 1 (f): the queue-full DLQ policy parks the excess delivery in
// DLQED with an audit row and keeps the earlier ones pending.
func TestQueueFullDLQParksExcess(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	policy := hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxQueue: 1}
	first := mustEnqueue(t, hs, hook.Event{HookID: d.ID, EventID: "evt-a", Policy: policy})
	second := mustEnqueue(t, hs, hook.Event{HookID: d.ID, EventID: "evt-b", Policy: policy})
	if second.State != hook.DeliveryDLQed {
		t.Fatalf("second = %q, want DLQED", second.State)
	}
	got, _ := hs.GetDelivery(first.ID)
	if got.State != hook.DeliveryPending {
		t.Fatalf("first = %q, want PENDING", got.State)
	}
}

// RED P16 Story 1 (g): a decommissioned node's deliveries are BOUNDED
// best-effort — they stay claimable until the decommission deadline and are
// then dropped with the DROPPED_DUE_TO_DECOMMISSION state (never retried,
// never delivering after the deadline).
func TestDecommissionDropAfterDeadline(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	delivery := mustEnqueue(t, hs, hook.Event{HookID: d.ID, EventID: "evt-dec", NodeID: "node-9", Payload: []byte(`{}`)})
	// Arm the deadline 30s in the future.
	if err := hs.MarkDecommissioned("node-9", 1_700_000_030); err != nil {
		t.Fatal(err)
	}
	// Before the deadline the delivery is still claimable (bounded best-effort).
	claimable, err := hs.ClaimDue(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimable) != 1 || claimable[0].ID != delivery.ID {
		t.Fatalf("pre-deadline claim = %+v", claimable)
	}
	// Advance the clock past the deadline (the claim pass then drops the
	// in-flight row: after the deadline it must NOT be delivered).
	hs.SetClock(func() time.Time { return time.Unix(1_700_000_031, 0) })
	if _, err := hs.ClaimDue(10); err != nil {
		t.Fatal(err)
	}
	got, err := hs.GetDelivery(delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != hook.DeliveryDroppedDecommission {
		t.Fatalf("post-deadline state = %q, want %q", got.State, hook.DeliveryDroppedDecommission)
	}
	events, err := hs.AdminEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev == "HOOK_DELIVERY_DROPPED_DUE_TO_DECOMMISSION" {
			found = true
		}
	}
	if !found {
		t.Fatal("decommission drop was not durably audited")
	}
}

// RED P16 Story 1 (h): the retry API requeues a DLQED delivery as PENDING with
// a fresh attempt budget.
func TestRetryDeliveryRequeuesDLQ(t *testing.T) {
	hs := newTestHookStore(t)
	d := mustDefinition(t, hs, "web", "https://example.com/hook")
	delivery := mustEnqueue(t, hs, hook.Event{
		HookID: d.ID, EventID: "evt-dlq",
		Policy: hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxAttempts: 1},
	})
	for i := 0; i < 1; i++ {
		claimed, err := hs.ClaimDue(10)
		if err != nil {
			t.Fatal(err)
		}
		if len(claimed) == 0 {
			t.Fatal("claim failed before retry")
		}
		_ = hs.MarkFailed(claimed[0].ID, "gone")
	}
	got, _ := hs.GetDelivery(delivery.ID)
	if got.State != hook.DeliveryDLQed {
		t.Fatalf("pre-retry state = %q, want DLQED", got.State)
	}
	retried, err := hs.RetryDelivery(delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.State != hook.DeliveryPending || retried.AttemptCount != 0 {
		t.Fatalf("retried = %+v", retried)
	}
}

// Unit proof of the bounded backoff curve (no jitter): 1,2,4,8,...,128 capped
// at 300 seconds.
func TestBackoffIsBounded(t *testing.T) {
	for attempt := 1; attempt <= 12; attempt++ {
		d := hook.BackoffSeconds(attempt)
		if d < 1 || d > 300 {
			t.Fatalf("attempt %d backoff = %d, want 1..300", attempt, d)
		}
	}
	if hook.BackoffSeconds(1) != 1 || hook.BackoffSeconds(2) != 2 {
		t.Fatalf("backoff curve wrong: %d %d", hook.BackoffSeconds(1), hook.BackoffSeconds(2))
	}
}

// TestOpenStoreFailsClosedOnUnmigratedDB: a hook store opened on a database
// that did not apply migration 0010 fails closed instead of failing at first use.
func TestOpenStoreFailsClosedOnUnmigratedDB(t *testing.T) {
	if _, err := hook.OpenStore(scratchDBPath(t)); err == nil {
		t.Fatal("hook store opened an unmigrated database")
	} else if !strings.Contains(err.Error(), "hook table") {
		t.Fatalf("unexpected fail-closed error: %v", err)
	}
}

func scratchDBPath(t *testing.T) string {
	t.Helper()
	// A fresh path is a valid empty database (migrations never applied).
	return filepath.Join(t.TempDir(), "fresh.db")
}
