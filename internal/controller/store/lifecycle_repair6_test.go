package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/recovery"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED R6-1: the durable store must admit at most one nonterminal rotation per
// signing scope. Before the partial unique invariant, both concurrent inserts
// succeeded and two PREPARED journals could compete for one staging slot.
func TestKeyRotationStoreAllowsOneNonterminalPerScope(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, conflicts int
	for _, id := range []string{"rot-scope-a", "rot-scope-b"} {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
				ID: id, Scope: "controller", OldKeyID: "old", NewKeyID: id,
				OldKeyGeneration: 1, NewGeneration: 2, Phase: "PREPARED",
				NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, store.ErrCASConflict):
				conflicts++
			default:
				t.Errorf("unexpected concurrent rotation insert error: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || conflicts != 1 {
		t.Fatalf("rotation insert outcomes successes=%d conflicts=%d, want one each", successes, conflicts)
	}
	ops, err := s.ListKeyRotationOperations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Phase != "PREPARED" || ops[0].Scope != "controller" {
		t.Fatalf("durable rotation rows=%+v, want one controller PREPARED row", ops)
	}
}

// RED R6-1: every nonterminal phase remains reserved for its signing scope;
// a second operation cannot be inserted after the first has advanced.
// RED R6-5 evidence: the exported restore API requires live store/key context;
// callers cannot bypass validation by supplying nil or an empty key-id set.
func TestApplyRestoreRequiresValidatedLiveContext(t *testing.T) {
	if _, err := recovery.ApplyRestore(context.Background(), nil, filepath.Join(t.TempDir(), "controller.db"), t.TempDir(), []string{"key-a"}); err == nil {
		t.Fatal("ApplyRestore accepted a nil live store")
	}
	live, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if _, err := recovery.ApplyRestore(context.Background(), live, live.Path(), t.TempDir(), nil); err == nil {
		t.Fatal("ApplyRestore accepted an empty live key-id set")
	}
}

func TestKeyRotationStoreRejectsSecondActiveScopeOperation(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-active-r6", Scope: "controller", OldKeyID: "old", NewKeyID: "new-a",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "ACTIVE",
		NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-second-r6", Scope: "controller", OldKeyID: "old", NewKeyID: "new-b",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "PREPARED",
		NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
	}); !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("second nonterminal rotation error=%v, want ErrCASConflict", err)
	}
}
