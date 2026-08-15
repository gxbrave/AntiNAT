package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func atomicForwardFixture(t *testing.T, s *store.Store, operationID string) (store.Forward, store.ForwardSpec, store.ControlOutboxItem, store.IdempotencyRecord) {
	t.Helper()
	f := store.Forward{
		ID: "fwd-bundle", NodeID: "node-1", Name: "bundle", Protocol: "tcp", Revision: 1,
	}
	spec := store.ForwardSpec{
		ID: "spec-bundle", ForwardID: f.ID, Revision: 1,
		SpecJSON: `{"forward_id":"fwd-bundle","name":"bundle","protocol":"tcp"}`,
	}
	outbox := store.ControlOutboxItem{
		OperationID: operationID, MessageType: "desired", NodeID: f.NodeID,
		SemanticPayload: `{"node_id":"node-1","forwards":[]}`, State: "PENDING",
	}
	idem := store.IdempotencyRecord{
		Key: "forward-bundle-key", Route: "/api/v1/forwards", Principal: "admin",
		RequestHash: "request-hash-1", ResponseStatus: 201,
		ResponseBody: `{"id":"fwd-bundle"}`,
	}
	return f, spec, outbox, idem
}

func TestCreateForwardBundleRollsBackEverySideEffectOnOutboxFault(t *testing.T) {
	s, _, existing := openTest(t)

	f, spec, outbox, idem := atomicForwardFixture(t, s, "bundle-op-conflict")
	if err := s.EnqueueControlOutbox(outbox); err != nil {
		t.Fatalf("pre-arm outbox: %v", err)
	}

	if _, _, err := s.CreateForwardBundle(context.Background(), f, spec, outbox, idem); err == nil {
		t.Fatal("CreateForwardBundle succeeded despite conflicting outbox row")
	}
	if got, err := s.ForwardCount(); err != nil || got != 1 {
		t.Fatalf("ForwardCount = %d (err %v), want existing row only", got, err)
	}
	if got, err := s.ForwardSpecCount(f.ID); err != nil || got != 0 {
		t.Fatalf("ForwardSpecCount = %d (err %v), want 0 after rollback", got, err)
	}
	if got, err := s.ControlOutboxCount(existing.NodeID); err != nil || got != 1 {
		t.Fatalf("ControlOutboxCount = %d (err %v), want pre-existing row only", got, err)
	}
	if _, err := s.GetIdempotency(idem.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("idempotency row survived failed bundle: %v", err)
	}
}

func TestCreateForwardBundleReplaysIdenticallyAndConflictsOnHashMismatch(t *testing.T) {
	s, _, _ := openTest(t)
	f, spec, outbox, idem := atomicForwardFixture(t, s, "bundle-op-success")

	stored, replayed, err := s.CreateForwardBundle(context.Background(), f, spec, outbox, idem)
	if err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	if replayed || stored.ResponseBody != idem.ResponseBody {
		t.Fatalf("first bundle result = %+v, replayed=%v", stored, replayed)
	}

	replayedRecord, replayed, err := s.CreateForwardBundle(context.Background(), f, spec, outbox, idem)
	if err != nil {
		t.Fatalf("identical replay: %v", err)
	}
	if !replayed || replayedRecord.ResponseBody != stored.ResponseBody {
		t.Fatalf("replay result = %+v, replayed=%v", replayedRecord, replayed)
	}
	if got, err := s.ForwardCount(); err != nil || got != 2 {
		t.Fatalf("ForwardCount = %d (err %v), duplicate forward was created", got, err)
	}
	if got, err := s.ForwardSpecCount(f.ID); err != nil || got != 1 {
		t.Fatalf("ForwardSpecCount = %d (err %v), duplicate spec was created", got, err)
	}

	conflict := idem
	conflict.RequestHash = "request-hash-2"
	if _, _, err := s.CreateForwardBundle(context.Background(), f, spec, outbox, conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("hash mismatch error = %v, want ErrIdempotencyConflict", err)
	}
	if got, err := s.ForwardCount(); err != nil || got != 2 {
		t.Fatalf("ForwardCount after conflict = %d (err %v), side effect occurred", got, err)
	}
}

func TestCreateForwardBundleConcurrentIdenticalRetryHasOneSideEffect(t *testing.T) {
	s, _, _ := openTest(t)
	f, spec, outbox, idem := atomicForwardFixture(t, s, "bundle-op-race")
	outbox.State = "SEMANTIC_ACKED" // creation must still fence the intent at PENDING

	const callers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	replayed := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, isReplay, err := s.CreateForwardBundle(context.Background(), f, spec, outbox, idem)
			if err != nil {
				errs <- err
				return
			}
			replayed <- isReplay
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(replayed)

	for err := range errs {
		t.Fatalf("concurrent bundle retry: %v", err)
	}
	firsts, retries := 0, 0
	for isReplay := range replayed {
		if isReplay {
			retries++
		} else {
			firsts++
		}
	}
	if firsts != 1 || retries != callers-1 {
		t.Fatalf("concurrent bundle results: firsts=%d retries=%d, want 1/%d", firsts, retries, callers-1)
	}
	if got, err := s.ForwardCount(); err != nil || got != 2 {
		t.Fatalf("ForwardCount = %d (err %v), want existing plus one created forward", got, err)
	}
	if got, err := s.ForwardSpecCount(f.ID); err != nil || got != 1 {
		t.Fatalf("ForwardSpecCount = %d (err %v), want one spec", got, err)
	}
	if got, err := s.ControlOutboxCount(f.NodeID); err != nil || got != 1 {
		t.Fatalf("ControlOutboxCount = %d (err %v), want one command", got, err)
	}
	rows, err := s.ListControlOutboxByState(f.NodeID, "PENDING")
	if err != nil || len(rows) != 1 {
		t.Fatalf("created outbox rows = %d (err %v), want one PENDING row", len(rows), err)
	}
}
