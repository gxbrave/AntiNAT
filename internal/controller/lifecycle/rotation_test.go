// P14 Story 4 (controller side): the key rotation operation journal with the
// PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED transitions, the signed
// certificate, the offline/une-ACKed normal-retire block, force retire, and the
// rotation x backup barrier.
package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/security"
)

// TestRotationFSMReachesRetired drives a full controller rotation lifecycle.
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
