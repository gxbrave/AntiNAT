package state

import (
	"errors"
	"sync"
	"testing"
)

func TestConcurrentStaleSessionWorkCannotMutateEitherSide(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(100, "current"); err != nil {
		t.Fatal(err)
	}

	const workers = 32
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			if worker%2 == 0 {
				_, err := store.ReceiveCommand(99, "stale", "message", "desired", "hash")
				errs <- err
				return
			}
			errs <- store.ClaimOutbox(99, "stale", "operation")
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrStaleSession) {
			t.Errorf("concurrent stale work error = %v, want ErrStaleSession", err)
		}
	}
}
