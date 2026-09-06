package probe

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestBackgroundErrorQueuePreservesOrderAndDistinctFailures(t *testing.T) {
	env := newTestEnv(t, false)
	first := errors.New("first lifecycle failure")
	second := errors.New("second lifecycle failure")

	env.manager.recordBackgroundError(first)
	env.manager.recordBackgroundError(second)

	if got := env.manager.BackgroundError(); !errors.Is(got, first) {
		t.Fatalf("first BackgroundError = %v, want %v", got, first)
	}
	if got := env.manager.BackgroundError(); !errors.Is(got, second) {
		t.Fatalf("second BackgroundError = %v, want %v", got, second)
	}
	if got := env.manager.BackgroundError(); got != nil {
		t.Fatalf("empty BackgroundError = %v, want nil", got)
	}
}

func TestBackgroundErrorQueueIsRaceSafeAndBounded(t *testing.T) {
	env := newTestEnv(t, false)
	const writers = 8
	const perWriter = 32
	var wg sync.WaitGroup
	wg.Add(writers)
	for writer := 0; writer < writers; writer++ {
		go func(writer int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				env.manager.recordBackgroundError(fmt.Errorf("writer %d error %d", writer, i))
			}
		}(writer)
	}
	wg.Wait()

	count := 0
	for env.manager.BackgroundError() != nil {
		count++
	}
	if count != maxBackgroundErrors {
		t.Fatalf("queued background errors = %d, want bounded capacity %d", count, maxBackgroundErrors)
	}
}
