package store

import (
	"database/sql"
	"fmt"
)

// This file contains the atomic Apply* operations that pair a durable change
// (desired spec / deletion operation) with its control-outbox entry in one
// SQLite transaction. If any step faults, every step rolls back (frozen
// state-model §3: intent is persisted before any side effect).

// ApplyForwardDesired atomically records a new desired-spec revision, bumps
// the forward parent revision (CAS), and enqueues the outbox command. A fault
// in any step rolls back all of them.
func (s *Store) ApplyForwardDesired(spec ForwardSpec, outbox ControlOutboxItem) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin desired tx: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.Exec(
		`INSERT INTO forward_specs (id, forward_id, revision, spec_json, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		spec.ID, spec.ForwardID, spec.Revision, spec.SpecJSON, now(),
	); err != nil {
		return fmt.Errorf("store: desired spec insert: %w", err)
	}

	res, err := tx.Exec(
		`UPDATE forwards SET revision = revision + 1, updated_at = ?
		  WHERE id = ? AND revision = ?`,
		now(), spec.ForwardID, spec.Revision-1,
	)
	if err != nil {
		return fmt.Errorf("store: desired parent bump: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: desired parent rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: forward %s revision %d", ErrCASConflict, spec.ForwardID, spec.Revision)
	}

	if err := insertOutboxTx(tx, outbox); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit desired tx: %w", err)
	}
	return nil
}

// ApplyForwardDelete atomically records a forward deletion operation and
// enqueues its delete command. The forward row itself is removed only after a
// durable receipt (P14 lifecycle); the intent and outbox commit together here.
func (s *Store) ApplyForwardDelete(op ForwardDeletionOperation, outbox ControlOutboxItem) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin forward delete tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO forward_deletion_operations
		    (id, forward_id, status, desired_revision, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		op.ID, op.ForwardID, orDefault(op.Status, "PENDING"), op.DesiredRevision, now(),
	); err != nil {
		return fmt.Errorf("store: forward delete op insert: %w", err)
	}
	if err := insertOutboxTx(tx, outbox); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit forward delete tx: %w", err)
	}
	return nil
}

// ApplyNodeDelete atomically records a node deletion operation and enqueues
// its decommission command.
func (s *Store) ApplyNodeDelete(op NodeDeletionOperation, outbox ControlOutboxItem) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin node delete tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO node_deletion_operations
		    (id, node_id, status, mode, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, orDefault(op.Status, "PENDING"), orDefault(op.Mode, "normal"), now(),
	); err != nil {
		return fmt.Errorf("store: node delete op insert: %w", err)
	}
	if err := insertOutboxTx(tx, outbox); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit node delete tx: %w", err)
	}
	return nil
}

func insertOutboxTx(tx *sql.Tx, item ControlOutboxItem) error {
	ts := now()
	if _, err := tx.Exec(
		`INSERT INTO control_outbox
		    (operation_id, message_type, node_id, semantic_payload, state,
		     attempt_count, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		item.OperationID, item.MessageType, item.NodeID, item.SemanticPayload,
		orDefault(item.State, "PENDING"), ts, ts,
	); err != nil {
		return fmt.Errorf("store: outbox insert: %w", err)
	}
	return nil
}
