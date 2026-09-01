// P14 Story 4: Controller-side key rotation operation journal (v0.8 §8.3).
//
// The Controller signing key (and by the same FSM the agent/master/hook/probe
// keys) rotate through PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED.
// The rotation certificate is signed by the OLD key and binds old/new key IDs,
// generations, pubkeys, not-before and the overlap deadline. An offline Agent
// that never ACKs blocks a normal retire; force retire bypasses the deadline
// and then requires manual re-pin/re-enroll. Every transition is a durable
// store row written before any external side effect.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// ErrRotationPhaseRefuses is the fail-closed phase transition error.
var ErrRotationPhaseRefuses = errors.New("lifecycle: key rotation phase refused")

// RotationFSMSingleStep mirrors the frozen key_rotation FSM (protocol.domain).
var RotationFSMSingleStep = map[[2]string]bool{
	{"PREPARED", "ANNOUNCED"}: true,
	{"ANNOUNCED", "ACKED"}:    true,
	{"ACKED", "ACTIVE"}:       true,
	{"ACTIVE", "RETIRED"}:     true,
}

// PrepareRotation creates the successor keyring (generation+1), signs the
// rotation certificate with the OLD key, and durably persists the PREPARED
// operation BEFORE any announce message is issued. The returned operation's
// certificate is the announce payload.
func PrepareRotation(ctx context.Context, s *store.Store, keyringDir string, oldKey *security.Keyring, scope string, operationID string, notBeforeUnix, overlapDeadlineUnix int64) (store.KeyRotationOperation, error) {
	if oldKey == nil {
		return store.KeyRotationOperation{}, errors.New("lifecycle: rotation requires the current keyring")
	}
	reservation, err := store.AcquireLifecycleReservation(ctx, s)
	if err != nil {
		return store.KeyRotationOperation{}, err
	}
	defer reservation.Release()
	if scope != "controller" {
		return store.KeyRotationOperation{}, fmt.Errorf("%w: controller rotation scope must be controller", ErrRotationPhaseRefuses)
	}
	if notBeforeUnix == 0 || overlapDeadlineUnix == 0 || notBeforeUnix > overlapDeadlineUnix {
		return store.KeyRotationOperation{}, fmt.Errorf("%w: malformed rotation validity window", ErrRotationPhaseRefuses)
	}
	// Generate and sign the successor without touching the active signer file.
	// PREPARED is the journal intent; only an explicit later activation may
	// replace the active keyring.
	newKey, err := oldKey.GenerateSuccessor()
	if err != nil {
		return store.KeyRotationOperation{}, fmt.Errorf("lifecycle: create successor keyring: %w", err)
	}
	oldPub := oldKey.PublicKey()
	newPub := newKey.PublicKey()
	cert := security.NewRotationCertificate(scope, oldPub, oldKey.Generation(), oldKey.KeyID(),
		newPub, newKey.Generation(), newKey.KeyID(), notBeforeUnix, overlapDeadlineUnix)
	if err := security.SignRotationCertificate(&cert, oldKey.PrivateKey()); err != nil {
		return store.KeyRotationOperation{}, fmt.Errorf("lifecycle: sign rotation certificate: %w", err)
	}
	encoded, err := cert.Encode()
	if err != nil {
		return store.KeyRotationOperation{}, err
	}
	op := store.KeyRotationOperation{
		ID: operationID, Scope: scope,
		OldKeyID: oldKey.KeyID(), OldKeyGeneration: oldKey.Generation(),
		NewKeyID: newKey.KeyID(), NewPublicKey: fmt.Sprintf("%x", newPub), NewGeneration: newKey.Generation(),
		Phase: "PREPARED", NotBeforeUnix: notBeforeUnix,
		OverlapDeadlineUnix: overlapDeadlineUnix, Certificate: encoded,
	}
	if err := s.CreateKeyRotationOperation(op); err != nil {
		return store.KeyRotationOperation{}, err
	}
	// Stage into a path tied to this operation. Never inspect or remove the
	// historical shared stage here: another durable operation may own it, and a
	// stale shared file must not be allowed to corrupt this operation's journal.
	if err := newKey.StageForOperation(keyringDir, operationID); err != nil {
		// The PREPARED row must never claim a successor exists when staging did
		// not complete. Remove the just-created intent so a retry can safely
		// regenerate and stage successor material while the old signer remains.
		if removeErr := s.DeleteKeyRotationOperation(operationID); removeErr != nil {
			return store.KeyRotationOperation{}, fmt.Errorf("lifecycle: stage successor keyring: %v (rollback prepared journal: %w)", err, removeErr)
		}
		return store.KeyRotationOperation{}, fmt.Errorf("lifecycle: stage successor keyring: %w", err)
	}
	return op, nil
}

// reconcilePreparedRotationLocked verifies one durable PREPARED operation
// while the caller holds the shared lifecycle reservation. Cleanup is scoped to
// the operation-specific stage and therefore cannot remove another successor.
func reconcilePreparedRotationLocked(s *store.Store, keyringDir, operationID string) error {
	op, err := s.GetKeyRotationOperation(operationID)
	if err != nil {
		return err
	}
	if op.Phase != "PREPARED" {
		return nil
	}
	staged, err := security.LoadStagedKeyringForOperation(keyringDir, operationID)
	if err == nil && staged.KeyID() == op.NewKeyID && staged.Generation() == op.NewGeneration {
		return nil
	}
	// Repair-5 could leave one legacy shared stage after a crash. Migrate it
	// only when its identity exactly matches this operation, and only after the
	// operation-specific copy is durable. A stale row whose identity differs
	// must never remove that shared material: a newer operation may own it.
	if errors.Is(err, os.ErrNotExist) {
		if legacy, legacyErr := security.LoadStagedKeyring(keyringDir); legacyErr == nil &&
			legacy.KeyID() == op.NewKeyID && legacy.Generation() == op.NewGeneration {
			if stageErr := legacy.StageForOperation(keyringDir, operationID); stageErr != nil {
				return fmt.Errorf("lifecycle: migrate legacy staged successor: %w", stageErr)
			}
			if removeErr := security.RemoveStaged(keyringDir); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return fmt.Errorf("lifecycle: remove migrated legacy staged successor: %w", removeErr)
			}
			return nil
		}
	}
	if removeErr := s.DeleteKeyRotationOperation(operationID); removeErr != nil {
		return fmt.Errorf("lifecycle: reconcile prepared rotation staging (%v): %w", err, removeErr)
	}
	if removeErr := security.RemoveStagedForOperation(keyringDir, operationID); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("lifecycle: remove unrecoverable staged successor: %w", removeErr)
	}
	return fmt.Errorf("lifecycle: prepared rotation successor is not recoverable: %w", err)
}

// ReconcilePreparedRotation verifies a durable PREPARED operation still has
// the exact successor material it declared. It is safe to invoke on startup or
// retry and preserves the old signer when staging is missing/corrupt.
func ReconcilePreparedRotation(ctx context.Context, s *store.Store, keyringDir, operationID string) error {
	reservation, err := store.AcquireLifecycleReservation(ctx, s)
	if err != nil {
		return err
	}
	defer reservation.Release()
	return reconcilePreparedRotationLocked(s, keyringDir, operationID)
}

// ReconcilePreparedRotations scans durable rotation intents and reconciles all
// PREPARED operations under one reservation. A stale row can only clean its own
// stage, and no concurrent PrepareRotation can interleave between rows.
func ReconcilePreparedRotations(ctx context.Context, s *store.Store, keyringDir string) error {
	reservation, err := store.AcquireLifecycleReservation(ctx, s)
	if err != nil {
		return err
	}
	defer reservation.Release()
	ops, err := s.ListKeyRotationOperations()
	if err != nil {
		return err
	}
	var firstErr error
	for _, op := range ops {
		if op.Phase != "PREPARED" {
			continue
		}
		if err := reconcilePreparedRotationLocked(s, keyringDir, op.ID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// AdvanceRotationPhase is the single-step FSM transition guard. A normal
// retire is refused before the overlap deadline or while any known Agent lacks
// a durable ACK. Force retire is an explicit atomic bypass.
func AdvanceRotationPhase(ctx context.Context, s *store.Store, operationID, next string, forceRetire bool) (store.KeyRotationOperation, error) {
	op, err := s.GetKeyRotationOperation(operationID)
	if err != nil {
		return store.KeyRotationOperation{}, err
	}
	if !RotationFSMSingleStep[[2]string{op.Phase, next}] {
		// Force retire fast-forwards an une-ACKed ACKED -> RETIRED through the
		// two legal single steps; the phase journal records RETIRED in ONE
		// atomic write (repair-1 L1), so a crash can never leave the row ACTIVE
		// while the operation claims RETIRED.
		if forceRetire && next == "RETIRED" && op.Phase == "ACKED" {
			if err := s.ForceRetireKeyRotationOperation(operationID); err != nil {
				return store.KeyRotationOperation{}, err
			}
			op.Phase = "RETIRED"
			return op, nil
		}
		return store.KeyRotationOperation{}, fmt.Errorf("%w: %s -> %s", ErrRotationPhaseRefuses, op.Phase, next)
	}
	if next == "RETIRED" && !forceRetire {
		if op.Phase != "ACTIVE" {
			return store.KeyRotationOperation{}, fmt.Errorf("%w: normal retire blocked until the rotation is ACTIVE (offline/une-ACKed Agent)", ErrRotationPhaseRefuses)
		}
		if time.Now().Unix() < op.OverlapDeadlineUnix {
			return store.KeyRotationOperation{}, fmt.Errorf("%w: overlap deadline has not passed", ErrRotationPhaseRefuses)
		}
		allACKed, err := s.AllRotationAgentsAcknowledged(operationID)
		if err != nil {
			return store.KeyRotationOperation{}, err
		}
		if !allACKed {
			return store.KeyRotationOperation{}, fmt.Errorf("%w: normal retire blocked until all Agents ACK", ErrRotationPhaseRefuses)
		}
	}
	if err := s.AdvanceKeyRotationPhaseCAS(operationID, op.Phase, next); err != nil {
		return store.KeyRotationOperation{}, err
	}
	op.Phase = next
	return op, nil
}

// ForceRetireRotatedKey is the post-retire re-enroll guard: no session or
// enrollment may proceed with the retired key after a force retire.
func ForceRetireRotatedKey(ctx context.Context, s *store.Store, operationID string) error {
	res, err := AdvanceRotationPhase(ctx, s, operationID, "RETIRED", true)
	if err != nil {
		return err
	}
	_ = res
	return nil
}

// RotationXBackupBarrier returns an error while any key rotation operation is
// not terminal (RETIRED), so backup/restore and key rotation stay mutually
// exclusive as the deep spec requires (§8.3 oscillation with backup/restore).
func RotationXBackupBarrier(ctx context.Context, s *store.Store) error {
	ops, err := s.ListKeyRotationOperations()
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.Phase != "RETIRED" {
			return fmt.Errorf("%w: active key rotation operation %q in phase %q blocks backup/restore", ErrRotationPhaseRefuses, op.ID, op.Phase)
		}
	}
	return nil
}
