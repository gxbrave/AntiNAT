package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Forward is the stable parent row (frozen state-model §1). CurrentActivationID
// is advanced only under a matching revision via CASForwardActivation.
type Forward struct {
	ID                  string
	NodeID              string
	Name                string
	Protocol            string
	CurrentActivationID string
	Revision            uint64
	CreatedAt           int64
	UpdatedAt           int64
}

// CreateForward inserts a forward row. Foreign keys are enforced, so NodeID
// must reference an existing node. Growth writes are refused under low-disk
// policy (delete paths are not).
func (s *Store) CreateForward(f Forward) (Forward, error) {
	if err := s.checkWriteCapacity(); err != nil {
		return Forward{}, err
	}
	ts := now()
	_, err := s.db.Exec(
		`INSERT INTO forwards (id, node_id, name, protocol, current_activation_id,
		                       revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.NodeID, f.Name, f.Protocol, f.CurrentActivationID, f.Revision, ts, ts,
	)
	if err != nil {
		return Forward{}, fmt.Errorf("store: create forward: %w", err)
	}
	return s.GetForward(f.ID)
}

// GetForward returns a forward row by ID.
func (s *Store) GetForward(id string) (Forward, error) {
	var f Forward
	err := s.db.QueryRow(
		`SELECT id, node_id, name, protocol, current_activation_id,
		        revision, created_at, updated_at
		   FROM forwards WHERE id = ?`, id,
	).Scan(&f.ID, &f.NodeID, &f.Name, &f.Protocol, &f.CurrentActivationID,
		&f.Revision, &f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Forward{}, ErrForwardNotFound
	}
	if err != nil {
		return Forward{}, fmt.Errorf("store: get forward: %w", err)
	}
	return f, nil
}

// CASForwardActivation atomically sets current_activation_id and bumps the
// revision, but only when the expected revision is current. It returns
// ErrCASConflict on a stale write, leaving the row untouched.
func (s *Store) CASForwardActivation(id string, expectedRevision uint64, newActivationID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin CAS forward activation: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`UPDATE forwards
		    SET current_activation_id = ?, revision = revision + 1, updated_at = ?
		  WHERE id = ? AND revision = ?`,
		newActivationID, now(), id, expectedRevision,
	)
	if err != nil {
		return fmt.Errorf("store: CAS forward activation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: CAS forward activation rows: %w", err)
	}
	if n != 1 {
		return ErrCASConflict
	}
	// The frozen runtime mirror has no generation column. Invalidate it in the
	// same transaction as every revision advance, including an advance that
	// keeps the same activation identifier, so Arm cannot reuse a prior-
	// generation snapshot as current evidence.
	if _, err := tx.Exec(`DELETE FROM forward_runtime_status WHERE forward_id = ?`, id); err != nil {
		return fmt.Errorf("store: invalidate forward runtime status: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit CAS forward activation: %w", err)
	}
	return nil
}

// DeleteForwardRow removes a forward row. Foreign keys cascade to specs,
// activations and runtime status; deletion operations are logical references
// and survive (frozen state-model §4).
func (s *Store) DeleteForwardRow(id string) error {
	res, err := s.db.Exec(`DELETE FROM forwards WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete forward: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete forward rows: %w", err)
	}
	if n != 1 {
		return ErrForwardNotFound
	}
	return nil
}

// ForwardSpec is an immutable desired-spec revision bound to a stable
// forwards parent (frozen state-model §1: specs never outlive the forward).
type ForwardSpec struct {
	ID        string
	ForwardID string
	Revision  uint64
	SpecJSON  string
	CreatedAt int64
}

// CreateForwardSpec inserts an immutable desired-spec revision. The foreign
// key to forwards is enforced; a spec without a stable parent is rejected.
func (s *Store) CreateForwardSpec(spec ForwardSpec) error {
	_, err := s.db.Exec(
		`INSERT INTO forward_specs (id, forward_id, revision, spec_json, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		spec.ID, spec.ForwardID, spec.Revision, spec.SpecJSON, now(),
	)
	if err != nil {
		return fmt.Errorf("store: create forward spec: %w", err)
	}
	return nil
}

// ForwardSpecCount returns the number of spec revisions recorded for a forward.
func (s *Store) ForwardSpecCount(forwardID string) (int, error) {
	var count int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM forward_specs WHERE forward_id = ?", forwardID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count forward specs: %w", err)
	}
	return count, nil
}

// ForwardCount returns the total number of forward rows (used by backup
// restore verification).
func (s *Store) ForwardCount() (int, error) {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM forwards").Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count forwards: %w", err)
	}
	return count, nil
}

// ForwardDeletionOperation is a durable forward-deletion intent/result record.
// It is independent of the forward row lifecycle.
type ForwardDeletionOperation struct {
	ID              string
	ForwardID       string
	Status          string
	DesiredRevision uint64
	CreatedAt       int64
	CompletedAt     int64
}

// CreateForwardDeletionOperation inserts a deletion operation.
func (s *Store) CreateForwardDeletionOperation(op ForwardDeletionOperation) error {
	_, err := s.db.Exec(
		`INSERT INTO forward_deletion_operations
		    (id, forward_id, status, desired_revision, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		op.ID, op.ForwardID, orDefault(op.Status, "PENDING"), op.DesiredRevision, now(),
	)
	if err != nil {
		return fmt.Errorf("store: create forward deletion operation: %w", err)
	}
	return nil
}

// GetForwardDeletionOperation returns a deletion operation by ID.
func (s *Store) GetForwardDeletionOperation(id string) (ForwardDeletionOperation, error) {
	var op ForwardDeletionOperation
	var completedAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT id, forward_id, status, desired_revision, created_at, completed_at
		   FROM forward_deletion_operations WHERE id = ?`, id,
	).Scan(&op.ID, &op.ForwardID, &op.Status, &op.DesiredRevision, &op.CreatedAt, &completedAt)
	op.CompletedAt = completedAt.Int64
	if errors.Is(err, sql.ErrNoRows) {
		return ForwardDeletionOperation{}, ErrNotFound
	}
	if err != nil {
		return ForwardDeletionOperation{}, fmt.Errorf("store: get forward deletion operation: %w", err)
	}
	return op, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
