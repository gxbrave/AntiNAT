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
	if _, err := os.Stat(filepath.Join(dir, security.KeyringStagedFile)); !os.IsNotExist(err) {
		t.Fatalf("staged successor exists after journal rejection: stat err=%v", err)
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

// TestRotationFSMReachesRetired drives a full controller rotation lifecycle.
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
	if err := os.Remove(filepath.Join(dir, security.KeyringStagedFile)); err != nil {
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
		t.Fatalf("prepare: %v", err)
	}
	if op.Phase != "PREPARED" || op.Certificate == "" {
		t.Fatalf("operation = %+v", op)
	}
	// The active signer remains generation 1; successor material is staged.
	active, err := security.LoadOrCreateKeyring(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if active.Generation() != 1 || active.KeyID() == op.NewKeyID {
		t.Fatalf("active signer unexpectedly changed generation/id = %d/%s", active.Generation(), active.KeyID())
	}
	if _, err := os.Stat(filepath.Join(dir, security.KeyringStagedFile)); err != nil {
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
	// Force retire bypasses, and the phase journal records RETIRED.
	res, err := AdvanceRotationPhase(ctx, s, "rot-2", "RETIRED", true)
	if err != nil {
		t.Fatalf("force retire: %v", err)
	}
	if res.Phase != "RETIRED" {
		t.Fatalf("phase = %s", res.Phase)
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
