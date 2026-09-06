// P14 Story 4 (controller side): the key rotation operation journal with the
// PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED transitions, the signed
// certificate, the offline/une-ACKed normal-retire block, force retire, and the
// rotation x backup barrier.
package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// TestPrepareRotationDoesNotStageBeforeJournalFailure is the R4-7 RED oracle:
// when PREPARED cannot be recorded, successor material must not appear on disk.
// Before the ordering fix, staging ran first and left controller-signing.key.stage
// behind after CreateKeyRotationOperation rejected the empty operation id.
func TestPrepareRotationDoesNotStageBeforeJournalFailure(t *testing.T) {
	s := openStore(t)
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := PrepareRotation(context.Background(), s, dir, oldKey, "controller", "", now, now+3600); err == nil {
		t.Fatal("rotation with empty operation id unexpectedly succeeded")
	}
	if entries, err := os.ReadDir(dir); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range entries {
			if entry.Name() == security.KeyringStagedFile || strings.HasPrefix(entry.Name(), security.KeyringStagedPrefix) {
				t.Fatalf("staged successor exists after journal rejection: %s", entry.Name())
			}
		}
	}
	active, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation() != oldKey.Generation() || active.KeyID() != oldKey.KeyID() {
		t.Fatalf("active signer changed after journal rejection: generation=%d key=%s", active.Generation(), active.KeyID())
	}
}

// RED R5-3: a staging failure must not leave a PREPARED operation without
// recoverable successor material. The old signer remains authoritative and a
// retry after the staging fault is repaired must be possible.
func TestPrepareRotationStagingFailureDoesNotLeavePreparedGap(t *testing.T) {
	s := openStore(t)
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(badDir, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := PrepareRotation(context.Background(), s, badDir, oldKey, "controller", "rot-stage-r5", now, now+3600); err == nil {
		t.Fatal("rotation unexpectedly succeeded with an unusable keyring directory")
	}
	if _, err := s.GetKeyRotationOperation("rot-stage-r5"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("staging failure left a durable PREPARED operation: %v", err)
	}
	active, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if active.KeyID() != oldKey.KeyID() || active.Generation() != oldKey.Generation() {
		t.Fatalf("active signer changed after staging failure: %s/%d", active.KeyID(), active.Generation())
	}
	if err := os.Remove(badDir); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRotation(context.Background(), s, dir, oldKey, "controller", "rot-stage-r5", now, now+3600); err != nil {
		t.Fatalf("retry after staging repair failed: %v", err)
	}
}

// TestReconcilePreparedRotationRejectsMissingSuccessor verifies an unrecoverable
// PREPARED row is explicitly removed while the old signer remains active.
func TestReconcilePreparedRotationRejectsMissingSuccessor(t *testing.T) {
	s := openStore(t)
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := PrepareRotation(context.Background(), s, dir, oldKey, "controller", "rot-reconcile-r5", now, now+3600); err != nil {
		t.Fatal(err)
	}
	if err := security.RemoveStagedForOperation(dir, "rot-reconcile-r5"); err != nil {
		t.Fatal(err)
	}
	if err := ReconcilePreparedRotation(context.Background(), s, dir, "rot-reconcile-r5"); err == nil {
		t.Fatal("missing staged successor was treated as recoverable")
	}
	if _, err := s.GetKeyRotationOperation("rot-reconcile-r5"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unrecoverable PREPARED operation remained after reconciliation: %v", err)
	}
	active, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if active.KeyID() != oldKey.KeyID() || active.Generation() != oldKey.Generation() {
		t.Fatalf("old signer changed during reconciliation: %s/%d", active.KeyID(), active.Generation())
	}
}

// RED R6-1: concurrent preparations for one controller signing scope must not
// create two journals or let one operation remove the other's staged material.
func TestPrepareRotationConcurrentScopeHasOneWinnerAndIsolatedStage(t *testing.T) {
	s := openStore(t)
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes int
	var refused []error
	for _, id := range []string{"rot-concurrent-a", "rot-concurrent-b"} {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := PrepareRotation(context.Background(), s, dir, oldKey, "controller", id, now, now+3600)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else {
				refused = append(refused, err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || len(refused) != 1 {
		t.Fatalf("concurrent PrepareRotation outcomes successes=%d refused=%d errors=%v, want one each", successes, len(refused), refused)
	}
	ops, err := s.ListKeyRotationOperations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Phase != "PREPARED" {
		t.Fatalf("rotation rows=%+v, want one PREPARED row", ops)
	}
	staged, err := security.LoadStagedKeyringForOperation(dir, ops[0].ID)
	if err != nil {
		t.Fatalf("winning operation stage unavailable: %v", err)
	}
	if staged.KeyID() != ops[0].NewKeyID || staged.Generation() != ops[0].NewGeneration {
		t.Fatalf("staged successor=%s/%d, journal=%s/%d", staged.KeyID(), staged.Generation(), ops[0].NewKeyID, ops[0].NewGeneration)
	}
	active, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation() != oldKey.Generation() || active.KeyID() != oldKey.KeyID() {
		t.Fatalf("old signer changed during concurrent prepare: %s/%d", active.KeyID(), active.Generation())
	}
}

// RED R6-1: reconciling a stale operation must not delete a valid successor
// staged for another operation. The fixture models a durable legacy/corrupt row
// alongside an operation-specific valid stage and is non-vacuous against the old
// shared cleanup path, which removed the single shared stage unconditionally.
func TestReconcilePreparedRotationsDoesNotDeleteAnotherOperationStage(t *testing.T) {
	s := openStore(t)
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	valid, err := oldKey.GenerateSuccessor()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "z-stale-a", Scope: "controller", OldKeyID: oldKey.KeyID(), OldKeyGeneration: 1,
		NewKeyID: "missing-a", NewGeneration: 2, Phase: "PREPARED", NotBeforeUnix: now,
		OverlapDeadlineUnix: now + 3600,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "a-valid-b", Scope: "agent", OldKeyID: oldKey.KeyID(), OldKeyGeneration: 1,
		NewKeyID: valid.KeyID(), NewGeneration: 2, Phase: "PREPARED", NotBeforeUnix: now,
		OverlapDeadlineUnix: now + 3600,
	}); err != nil {
		t.Fatal(err)
	}
	// Keep a legacy shared stage too: this is the exact R6-1 failure mode
	// where stale A cleanup used to remove valid B's material.
	if err := valid.Stage(dir); err != nil {
		t.Fatal(err)
	}
	if err := valid.StageForOperation(dir, "a-valid-b"); err != nil {
		t.Fatal(err)
	}
	if err := ReconcilePreparedRotations(context.Background(), s, dir); err == nil {
		t.Fatal("reconciliation unexpectedly reported all prepared rows recoverable")
	}
	if _, err := s.GetKeyRotationOperation("z-stale-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale operation was not explicitly removed: %v", err)
	}
	remaining, err := s.GetKeyRotationOperation("a-valid-b")
	if err != nil {
		t.Fatalf("valid operation removed with stale predecessor: %v", err)
	}
	if remaining.Phase != "PREPARED" {
		t.Fatalf("valid operation phase=%q, want PREPARED", remaining.Phase)
	}
	staged, err := security.LoadStagedKeyringForOperation(dir, "a-valid-b")
	if err != nil {
		t.Fatalf("valid operation stage removed by stale cleanup: %v", err)
	}
	if staged.KeyID() != valid.KeyID() {
		t.Fatalf("valid stage key=%q, want %q", staged.KeyID(), valid.KeyID())
	}
	active, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if active.KeyID() != oldKey.KeyID() || active.Generation() != oldKey.Generation() {
		t.Fatalf("old signer changed during reconciliation: %s/%d", active.KeyID(), active.Generation())
	}
}

func TestRotationFSMReachesRetired(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Unix() - 3600
	op, err := PrepareRotation(ctx, s, dir, oldKey, "controller", "rot-1", notBefore, notBefore+1)
	if err != nil {
		t.Fatal(err)
	}
	if op.Phase != "PREPARED" || op.Certificate == "" {
		t.Fatalf("operation = %+v", op)
	}
	active, err := security.LoadOrCreateKeyring(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation() != 1 || active.KeyID() == op.NewKeyID {
		t.Fatalf("active signer unexpectedly changed generation/id = %d/%s", active.Generation(), active.KeyID())
	}
	if _, err := security.LoadStagedKeyringForOperation(dir, "rot-1"); err != nil {
		t.Fatalf("staged successor missing: %v", err)
	}
	for _, step := range []struct {
		next  string
		force bool
	}{
		{"ANNOUNCED", false},
		{"ACKED", false},
		{"ACTIVE", false},
		{"RETIRED", false},
	} {
		res, err := AdvanceRotationPhase(ctx, s, "rot-1", step.next, step.force)
		if err != nil {
			t.Fatalf("advance to %s: %v", step.next, err)
		}
		if res.Phase != step.next {
			t.Fatalf("phase = %s, want %s", res.Phase, step.next)
		}
	}
	stored, err := s.GetKeyRotationOperation("rot-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Phase != "RETIRED" {
		t.Fatalf("durable phase = %s", stored.Phase)
	}
	if err := RotationXBackupBarrier(ctx, s); err != nil {
		t.Fatalf("terminal rotation must not block backup: %v", err)
	}
}

// TestNormalRetireBlockedUntilActive is the offline/une-ACKed rule: RETIRED is
// refused from ACKED in a normal retire.
func TestNormalRetireBlockedUntilActive(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := PrepareRotation(ctx, s, dir, oldKey, "controller", "rot-2", now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-2", "ANNOUNCED", false); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-2", "ACKED", false); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-2", "RETIRED", false); err == nil {
		t.Fatal("normal retire from ACKED must be blocked (offline/une-ACKed Agent)")
	}
	res, err := AdvanceRotationPhase(ctx, s, "rot-2", "RETIRED", true)
	if err != nil {
		t.Fatalf("force retire: %v", err)
	}
	if res.Phase != "RETIRED" {
		t.Fatalf("phase = %s", res.Phase)
	}
}

// RED R6-5: normal retirement must first honor the overlap deadline and then
// require every known Agent's durable ACK. This reasserts both retirement gates
// at the lifecycle policy boundary, not only the lower-level ACK counter.
func TestNormalRetireRequiresDeadlineAndAllAgentACK(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.CreateNode(store.Node{ID: "node-retire-r6", Name: "node-retire-r6"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-deadline-r6", Scope: "controller", OldKeyID: "old", NewKeyID: "new-deadline",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "ACTIVE", NotBeforeUnix: 1,
		OverlapDeadlineUnix: time.Now().Unix() + 3600,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-deadline-r6", "RETIRED", false); err == nil || !strings.Contains(err.Error(), "overlap deadline") {
		t.Fatalf("normal retire before deadline error=%v, want overlap-deadline refusal", err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-deadline-r6", "RETIRED", true); err != nil {
		t.Fatal(err)
	}

	if err := s.CreateKeyRotationOperation(store.KeyRotationOperation{
		ID: "rot-ack-r6", Scope: "controller", OldKeyID: "old", NewKeyID: "new-ack",
		OldKeyGeneration: 1, NewGeneration: 2, Phase: "ACTIVE", NotBeforeUnix: 1,
		OverlapDeadlineUnix: time.Now().Unix() - 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-ack-r6", "RETIRED", false); err == nil || !strings.Contains(err.Error(), "all Agents ACK") {
		t.Fatalf("normal retire after deadline error=%v, want unacknowledged-agent refusal", err)
	}
	if err := s.RecordKeyRotationAgentACK("rot-ack-r6", "node-retire-r6"); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceRotationPhase(ctx, s, "rot-ack-r6", "RETIRED", false); err != nil {
		t.Fatalf("normal retire after deadline + durable ACK: %v", err)
	}
}

// TestRotationBarrierBlocksBackup: an in-flight rotation blocks backup/restore.
func TestRotationBarrierBlocksBackup(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := PrepareRotation(ctx, s, dir, oldKey, "controller", "rot-3", now, now+3600); err != nil {
		t.Fatal(err)
	}
	if err := RotationXBackupBarrier(ctx, s); err == nil {
		t.Fatal("backup barrier must block while a rotation is non-terminal")
	}
}

// TestDowngradeLoadRefused: after a real rotation writes generation 2, a
// LoadOrCreate that TRIES to create generation 1 must read the on-disk
// generation-2 key — a post-rotation downgrade attempt can never overwrite it.
func TestDowngradeLoadRefused(t *testing.T) {
	dir := t.TempDir()
	k1, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := k1.Rotate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if next.Generation() != 2 {
		t.Fatalf("rotated generation = %d", next.Generation())
	}
	reloaded, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Generation() != 2 || reloaded.KeyID() != next.KeyID() {
		t.Fatalf("downgrade attempt reloaded generation/id %d/%s, want %d/%s",
			reloaded.Generation(), reloaded.KeyID(), next.Generation(), next.KeyID())
	}
}
