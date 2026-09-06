package store_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED R4-1: two callers validating PREPARED concurrently must not both advance
// the same durable row. The pre-fix unconditional UPDATE lets both writes win.
func TestRotationPhaseCASAllowsOneConcurrentAdvance(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-cas", Scope: "controller", OldKeyID: "old", NewKeyID: "new",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "PREPARED",
		NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, conflicts int
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.AdvanceKeyRotationPhaseCAS("rot-cas", "PREPARED", "ANNOUNCED")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, store.ErrCASConflict):
				conflicts++
			default:
				t.Errorf("unexpected concurrent transition error: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS outcomes successes=%d conflicts=%d, want one each", successes, conflicts)
	}
	got, err := s.GetKeyRotationOperation("rot-cas")
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != "ANNOUNCED" {
		t.Fatalf("phase=%q, want ANNOUNCED", got.Phase)
	}
}

// RED R4-1: direct store callers must not skip or regress the rotation FSM.
func TestRotationStoreRejectsInvalidNextPhase(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-fsm", Scope: "controller", OldKeyID: "old", NewKeyID: "new",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "PREPARED",
		NotBeforeUnix: 1, OverlapDeadlineUnix: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceKeyRotationPhase("rot-fsm", "ACTIVE"); !errors.Is(err, store.ErrIllegalPhase) {
		t.Fatalf("skip transition error=%v, want ErrIllegalPhase", err)
	}
	if err := s.AdvanceKeyRotationPhase("rot-fsm", "ANNOUNCED"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceKeyRotationPhaseCAS("rot-fsm", "ANNOUNCED", "PREPARED"); !errors.Is(err, store.ErrIllegalPhase) {
		t.Fatalf("backward transition error=%v, want ErrIllegalPhase", err)
	}
}

// RED R4-3: a node quarantine cannot be cleared by an unknown or stale restore
// operation, nor while the matching operation is not AUTHORIZED.
func TestReauthorizeNodeRequiresCurrentAuthorizedRestoreOperation(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateNode(store.Node{ID: "node-restore-r4", Name: "node-restore-r4"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnterRestoreReconciliation(store.RestoreOperation{ID: "restore-a", ManifestSHA256: "a", SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeNodeForOperation("node-restore-r4", "unknown"); err == nil {
		t.Fatal("unknown restore operation cleared quarantine")
	}
	if err := s.ReauthorizeNodeForOperation("node-restore-r4", "restore-a"); err == nil {
		t.Fatal("restore operation in reconciliation phase cleared quarantine")
	}
	if err := s.AdvanceRestorePhase("restore-a", "AUTHORIZED"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnterRestoreReconciliation(store.RestoreOperation{ID: "restore-b", ManifestSHA256: "b", SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceRestorePhase("restore-b", "AUTHORIZED"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeNodeForOperation("node-restore-r4", "restore-a"); err == nil {
		t.Fatal("stale restore operation cleared quarantine bound to restore-b")
	}
	if err := s.ReauthorizeNodeForOperation("node-restore-r4", "restore-b"); err != nil {
		t.Fatalf("current authorized restore operation refused: %v", err)
	}
	quarantined, err := s.IsNodeQuarantined("node-restore-r4")
	if err != nil || quarantined {
		t.Fatalf("quarantine=%v err=%v after matching reauthorization", quarantined, err)
	}
}

// RED R4-9: normal retirement must wait for the overlap deadline and every
// required node ACK; force retirement remains an explicit bypass.
func TestRotationRetireRequiresDeadlineAndAgentACK(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateNode(store.Node{ID: "node-ack-r4", Name: "node-ack-r4"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-retire-r4", Scope: "controller", OldKeyID: "old", NewKeyID: "new",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "ACTIVE",
		NotBeforeUnix: 1, OverlapDeadlineUnix: 4102444800,
	}); err != nil {
		t.Fatal(err)
	}
	// The lifecycle package owns the wall-clock/deadline policy; this store test
	// only proves durable ACK tracking has a per-node identity and is not implicit.
	if ok, err := s.AllRotationAgentsAcknowledged("rot-retire-r4"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("unacknowledged required node reported as acknowledged")
	}
	if err := s.RecordKeyRotationAgentACK("rot-retire-r4", "node-ack-r4"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.AllRotationAgentsAcknowledged("rot-retire-r4"); err != nil || !ok {
		t.Fatalf("ACK tracking result=%v err=%v, want true", ok, err)
	}
}
