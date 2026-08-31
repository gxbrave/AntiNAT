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
	newKey, err := oldKey.Rotate(keyringDir)
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
	return op, nil
}

// AdvanceRotationPhase is the single-step FSM transition guard. A normal
// retire is refused while the operation is not ACTIVE (the offline/une-ACKed
// block); force retire transitions from ACTIVE regardless and the caller
// records that manual re-pin/re-enroll is now required.
func AdvanceRotationPhase(ctx context.Context, s *store.Store, operationID, next string, forceRetire bool) (store.KeyRotationOperation, error) {
	op, err := s.GetKeyRotationOperation(operationID)
	if err != nil {
		return store.KeyRotationOperation{}, err
	}
	if !RotationFSMSingleStep[[2]string{op.Phase, next}] {
		// Force retire may fast-forward ACKED -> ACTIVE -> RETIRED through the
		// two legal single steps; the phase journal records both.
		if forceRetire && next == "RETIRED" && op.Phase == "ACKED" {
			if err := s.AdvanceKeyRotationPhase(operationID, "ACTIVE"); err != nil {
				return store.KeyRotationOperation{}, err
			}
			if err := s.AdvanceKeyRotationPhase(operationID, "RETIRED"); err != nil {
				return store.KeyRotationOperation{}, err
			}
			op.Phase = "RETIRED"
			return op, nil
		}
		return store.KeyRotationOperation{}, fmt.Errorf("%w: %s -> %s", ErrRotationPhaseRefuses, op.Phase, next)
	}
	if next == "RETIRED" && !forceRetire && op.Phase != "ACTIVE" {
		return store.KeyRotationOperation{}, fmt.Errorf("%w: normal retire blocked until the rotation is ACTIVE (offline/une-ACKed Agent)", ErrRotationPhaseRefuses)
	}
	if err := s.AdvanceKeyRotationPhase(operationID, next); err != nil {
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
