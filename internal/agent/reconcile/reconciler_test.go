package reconcile

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// reconciler.go RED: the reconcile control loop applies desired, records
// durable deletion results, refuses to run decommissioned, and survives actor
// panics without stopping the loop.

func TestReconcileOnceAppliesAndRecordsDeletionResult(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error { return nil })

	d := testDesired(present("fwd-a", 1), absent("fwd-b", "del-op-b", 1))
	report, err := reconciler.ReconcileOnce(context.Background(), d, 1, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != localstate.ApplyStatusFull {
		t.Fatalf("report status = %v, want FULL", report.Status)
	}
	// fwd-a applied, fwd-b tombstoned.
	if _, ok, err := store.GetAppliedState("fwd-a"); err != nil || !ok {
		t.Fatalf("fwd-a applied present=%v err=%v", ok, err)
	}
	if ok, err := store.TombstoneExists("fwd-b"); err != nil || !ok {
		t.Fatalf("fwd-b tombstone present=%v err=%v", ok, err)
	}
	// The durable deletion result must be queued to the outbox.
	state, present, err := store.OutboxState("del-op-b")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("del-op-b outbox = %q present=%v err=%v, want PENDING", state, present, err)
	}
}

func TestReconcileOnceWithoutSessionSkipsResultRecording(t *testing.T) {
	store := testStore(t)
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive, nil,
		func(ctx context.Context, forwardID string) error { return nil })
	report, err := reconciler.ReconcileOnce(context.Background(), testDesired(absent("fwd-c", "del-op-c", 1)), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-c" && r.Outcome != OutcomeDeleted {
			t.Fatalf("result = %+v, want OutcomeDeleted", r)
		}
	}
	// No session: the tombstone is durable but no result is queued yet.
	if ok, err := store.TombstoneExists("fwd-c"); err != nil || !ok {
		t.Fatalf("tombstone present=%v err=%v", ok, err)
	}
	if store.OutboxContains("del-op-c") {
		t.Fatal("deletion result queued without a session; want skipped")
	}
}

func TestReconcileOnceRefusesWhenDecommissioned(t *testing.T) {
	store := testStore(t)
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerDecommissioned, nil, nil)
	_, err := reconciler.ReconcileOnce(context.Background(), testDesired(present("fwd-x", 1)), 1, "s")
	if !errors.Is(err, ErrDecommissioned) {
		t.Fatalf("decommissioned reconcile error = %v, want ErrDecommissioned", err)
	}
}

func TestReconcileRunLoopSurvivesActorPanicAndProcessesTriggers(t *testing.T) {
	store := testStore(t)
	// Seed the received desired so each loop trigger actually reconciles and
	// starts the panicking actor through the apply hook.
	if err := store.SaveReceivedDesired(testDesired(present("panic-fwd", 1))); err != nil {
		t.Fatal(err)
	}
	supervisor := NewSupervisor()
	panicActor := &funcActor{name: "panic-fwd", run: func(ctx context.Context) error { panic("boom") }}
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			// The hook starts a panicking actor; the supervisor contains the
			// panic and the control loop must not stop.
			if err := supervisor.Start(ctx, panicActor); err != nil {
				return protocol.AppliedForwardState{}, err
			}
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error { return nil })

	trigger := make(chan struct{}, 2)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- reconciler.Run(ctx, trigger) }()

	trigger <- struct{}{}
	trigger <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("loop exited early: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop exit error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop on cancel")
	}
	// The panicking actor was reported PANICKED and everything else survived.
	sawPanic := false
	deadline := time.After(time.Second)
readLoop:
	for !sawPanic {
		select {
		case result := <-supervisor.Results():
			if result.Actor == "panic-fwd" && result.Outcome == ActorPanicked {
				sawPanic = true
			}
		case <-deadline:
			break readLoop
		}
	}
	if !sawPanic {
		t.Fatal("actor panic was not reported by the supervisor")
	}
}

func TestReconcileOnceActorPanicDoesNotFailTheReconcile(t *testing.T) {
	store := testStore(t)
	supervisor := NewSupervisor()
	var calls atomic.Int64
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			calls.Add(1)
			_ = supervisor.Start(ctx, &funcActor{name: "boom", run: func(ctx context.Context) error { panic("x") }})
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		nil)
	report, err := reconciler.ReconcileOnce(context.Background(), testDesired(present("fwd-p", 1)), 0, "")
	if err != nil {
		t.Fatalf("reconcile with panicking actor errored: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("apply hook calls = %d, want 1", calls.Load())
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-p" && r.Outcome != OutcomeApplied {
			t.Fatalf("result = %+v, want OutcomeApplied", r)
		}
	}
}
