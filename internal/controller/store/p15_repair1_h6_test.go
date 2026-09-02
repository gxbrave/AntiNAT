package store_test

// P15 repair cycle-1 RED H6 store tests: PutNavigationOrder and
// PutSettingsRecord previously had a read-check-write without a durable
// conditional write, so two concurrent writers with the same expected revision
// could both pass the read and lose one update. The WHERE revision guard makes
// the CAS durable and the loser maps to ErrCASConflict (412 in the API).

import (
	"errors"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair1H6NavigationOrderConcurrentCASOneWinner(t *testing.T) {
	s := openRepairStore(t)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Empty ID lists keep validateIDs a no-op; the concurrency oracle is
			// purely the revision guard.
			_, results[idx] = s.PutNavigationOrder(0, store.NavigationOrder{})
		}(i)
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, store.ErrCASConflict):
			conflict++
		default:
			t.Fatalf("unexpected PutNavigationOrder error: %v", err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("concurrent navigation order = %d winners %d conflicts, want exactly one winner", ok, conflict)
	}
}

func TestP15Repair1H6SettingsPUTStaleExpectedIsCASConflict(t *testing.T) {
	s := openRepairStore(t)
	rec, err := s.GetSettingsRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Revision != 0 {
		t.Fatalf("initial settings revision = %d, want 0", rec.Revision)
	}
	updated, err := s.PutSettingsRecord(0, `{"language":"en"}`)
	if err != nil || updated.Revision != 1 {
		t.Fatalf("first settings PUT = %+v err %v", updated, err)
	}
	if _, err := s.PutSettingsRecord(0, `{"language":"zh"}`); !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("stale settings PUT = %v, want ErrCASConflict", err)
	}
}
