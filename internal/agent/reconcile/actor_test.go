package reconcile

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Story 6 RED: one actor panic/failure must not stop a sibling or the control
// loop; the lifecycle interface is bounded and the supervisor reports
// per-actor results.

func TestActorPanicDoesNotStopSiblingsOrSupervisor(t *testing.T) {
	supervisor := NewSupervisor()
	var panicked atomic.Bool
	var completed atomic.Int64

	panicActor := &funcActor{
		name: "panic-actor",
		run: func(ctx context.Context) error {
			panicked.Store(true)
			panic("boom: actor blew up")
		},
	}
	goodActor := &funcActor{
		name: "good-actor",
		run: func(ctx context.Context) error {
			completed.Add(1)
			return nil
		},
	}
	second := &funcActor{
		name: "second-actor",
		run: func(ctx context.Context) error {
			completed.Add(1)
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, panicActor); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, goodActor); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, second); err != nil {
		t.Fatal(err)
	}
	supervisor.Wait()

	if !panicked.Load() {
		t.Fatal("panic actor never ran")
	}
	if completed.Load() != 2 {
		t.Fatalf("sibling completions = %d, want 2 (siblings must not stop)", completed.Load())
	}
	var sawPanic, sawCompleted bool
	for i := 0; i < 3; i++ {
		select {
		case result := <-supervisor.Results():
			if result.Actor == "panic-actor" {
				if result.Outcome != ActorPanicked {
					t.Fatalf("panic actor outcome = %v, want ActorPanicked", result.Outcome)
				}
				if result.Err == nil || !errors.Is(result.Err, ErrActorPanicked) {
					t.Fatalf("panic actor error = %v, want ErrActorPanicked", result.Err)
				}
				sawPanic = true
			}
			if result.Actor == "good-actor" || result.Actor == "second-actor" {
				if result.Outcome != ActorCompleted {
					t.Fatalf("sibling %s outcome = %v, want ActorCompleted", result.Actor, result.Outcome)
				}
				sawCompleted = true
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for result %d", i)
		}
	}
	if !sawPanic || !sawCompleted {
		t.Fatalf("results missing panic=%v completed=%v", sawPanic, sawCompleted)
	}
}

func TestSupervisorReportsActorFailure(t *testing.T) {
	supervisor := NewSupervisor()
	failErr := errors.New("actor run failure")
	failing := &funcActor{name: "failing", run: func(ctx context.Context) error { return failErr }}
	ctx := context.Background()
	if err := supervisor.Start(ctx, failing); err != nil {
		t.Fatal(err)
	}
	supervisor.Wait()
	result := <-supervisor.Results()
	if result.Actor != "failing" || result.Outcome != ActorFailed || !errors.Is(result.Err, failErr) {
		t.Fatalf("result = %+v, want failing/ActorFailed/failErr", result)
	}
}

func TestSupervisorStartIsBounded(t *testing.T) {
	supervisor := NewSupervisor(WithMaxConcurrentActors(2))
	blocker := make(chan struct{})
	blocked := &funcActor{
		name: "blocked",
		run: func(ctx context.Context) error {
			<-blocker
			return nil
		},
	}
	ctx := context.Background()
	if err := supervisor.Start(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, &funcActor{name: "b2", run: func(ctx context.Context) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, &funcActor{name: "b3", run: func(ctx context.Context) error { return nil }}); !errors.Is(err, ErrSupervisorFull) {
		t.Fatalf("start beyond bound error = %v, want ErrSupervisorFull", err)
	}
	close(blocker)
	supervisor.Wait()
}

func TestSupervisorStartTimeoutBoundsLifecycle(t *testing.T) {
	supervisor := NewSupervisor(WithStartTimeout(50 * time.Millisecond))
	slow := &funcActor{
		name: "slow-start",
		start: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		run: func(ctx context.Context) error { return nil },
	}
	ctx := context.Background()
	err := supervisor.Start(ctx, slow)
	if err == nil {
		supervisor.Wait()
		t.Fatal("start of never-ready actor succeeded; want bounded timeout failure")
	}
	result := <-supervisor.Results()
	if result.Actor != "slow-start" || result.Outcome != ActorStartFailed {
		t.Fatalf("result = %+v, want slow-start/ActorStartFailed", result)
	}
}

// funcActor is a scriptable Actor used by the Story 6 tests.
type funcActor struct {
	name  string
	start func(ctx context.Context) error
	run   func(ctx context.Context) error
	stop  func(ctx context.Context) error
}

func (f *funcActor) Name() string { return f.name }
func (f *funcActor) Start(ctx context.Context) error {
	if f.start != nil {
		return f.start(ctx)
	}
	return nil
}
func (f *funcActor) Run(ctx context.Context) error {
	if f.run != nil {
		return f.run(ctx)
	}
	return nil
}
func (f *funcActor) Stop(ctx context.Context) error {
	if f.stop != nil {
		return f.stop(ctx)
	}
	return nil
}
