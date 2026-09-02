package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// This file contains the atomic Apply* operations that pair a durable change
// (desired spec / deletion operation) with its control-outbox entry in one
// SQLite transaction. If any step faults, every step rolls back (frozen
// state-model §3: intent is persisted before any side effect).

// ApplyForwardDesired atomically records a new desired-spec revision, bumps
// the forward parent revision (CAS), and enqueues the outbox command. A fault
// in any step rolls back all of them. BEGIN IMMEDIATE is intentional (repair-1
// H6): a deferred read-implied transaction can hit SQLITE_BUSY_SNAPSHOT when a
// concurrent control-plane writer commits between the parent read and the CAS
// update, which the API would surface as a 500 instead of a 412. Serializing
// the writer decision lets the loser observe the new revision and return the
// typed CAS conflict.
func (s *Store) ApplyForwardDesired(spec ForwardSpec, outbox ControlOutboxItem) error {
	if spec.ForwardID == "" || outbox.OperationID == "" {
		return fmt.Errorf("%w: desired identity", ErrIdempotencyConflict)
	}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: desired conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin desired tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO forward_specs (id, forward_id, revision, spec_json, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		spec.ID, spec.ForwardID, spec.Revision, spec.SpecJSON, now(),
	); err != nil {
		return fmt.Errorf("store: desired spec insert: %w", err)
	}

	activation := protocol.ActivationID(spec.ForwardID, spec.Revision)
	res, err := conn.ExecContext(ctx,
		`UPDATE forwards SET current_activation_id = ?, revision = revision + 1, updated_at = ?
		  WHERE id = ? AND revision = ?`,
		hex.EncodeToString(activation[:]), now(), spec.ForwardID, spec.Revision-1,
	)
	if err != nil {
		return fmt.Errorf("store: desired parent bump: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: desired parent rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: forward %s revision %d", ErrCASConflict, spec.ForwardID, spec.Revision)
	}

	if err := insertOutboxExec(ctx, conn, outbox); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit desired tx: %w", err)
	}
	committed = true
	return nil
}

// ApplyForwardDelete atomically records a forward deletion operation and
// enqueues its delete command. The forward row itself is removed only after a
// durable receipt (P14 lifecycle); the intent and outbox commit together here.
// BEGIN IMMEDIATE is intentional: a deferred read-then-write transaction can
// hit SQLITE_BUSY_SNAPSHOT when a control-plane writer commits between the
// revision read and the CAS update. Serializing the writer decision lets the
// loser observe the new revision and return the typed CAS conflict instead.
func (s *Store) ApplyForwardDelete(op ForwardDeletionOperation, outbox ControlOutboxItem) error {
	if op.ID == "" || outbox.OperationID != op.ID {
		return fmt.Errorf("%w: deletion operation/outbox identity", ErrIdempotencyConflict)
	}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: forward delete conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin forward delete tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	// A retried operation id is a replay of the same durable intent. Return
	// success only when its immutable binding and queued payload agree; do not
	// bump the parent revision or enqueue a second side effect.
	var existingForward string
	var existingRevision uint64
	err = conn.QueryRowContext(ctx, `SELECT forward_id, desired_revision FROM forward_deletion_operations WHERE id = ?`, op.ID).
		Scan(&existingForward, &existingRevision)
	if err == nil {
		if existingForward != op.ForwardID || existingRevision != op.DesiredRevision {
			return fmt.Errorf("%w: deletion operation %s", ErrIdempotencyConflict, op.ID)
		}
		var existingNode, existingPayload string
		if err := conn.QueryRowContext(ctx, `SELECT node_id, semantic_payload FROM control_outbox WHERE operation_id = ? AND message_type = ?`, outbox.OperationID, outbox.MessageType).
			Scan(&existingNode, &existingPayload); err != nil {
			return fmt.Errorf("store: verify replayed delete outbox: %w", err)
		}
		if existingNode != outbox.NodeID || existingPayload != outbox.SemanticPayload {
			return fmt.Errorf("%w: deletion outbox %s", ErrIdempotencyConflict, outbox.OperationID)
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return fmt.Errorf("store: commit replayed forward delete tx: %w", err)
		}
		committed = true
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("store: check forward delete operation: %w", err)
	}

	var currentRevision uint64
	if err := conn.QueryRowContext(ctx, `SELECT revision FROM forwards WHERE id = ?`, op.ForwardID).Scan(&currentRevision); err == sql.ErrNoRows {
		return ErrForwardNotFound
	} else if err != nil {
		return fmt.Errorf("store: read forward delete parent: %w", err)
	}
	if currentRevision != op.DesiredRevision {
		return fmt.Errorf("%w: forward %s revision %d", ErrCASConflict, op.ForwardID, op.DesiredRevision)
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO forward_deletion_operations
		    (id, forward_id, status, desired_revision, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		op.ID, op.ForwardID, orDefault(op.Status, "PENDING"), op.DesiredRevision, now(),
	); err != nil {
		return fmt.Errorf("store: forward delete op insert: %w", err)
	}
	res, err := conn.ExecContext(ctx, `UPDATE forwards SET revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ?`, now(), op.ForwardID, op.DesiredRevision)
	if err != nil {
		return fmt.Errorf("store: forward delete parent bump: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: forward delete parent rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: forward %s revision %d", ErrCASConflict, op.ForwardID, op.DesiredRevision)
	}
	if err := insertOutboxExec(ctx, conn, outbox); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit forward delete tx: %w", err)
	}
	committed = true
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

type sqlContextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertOutboxTx(tx *sql.Tx, item ControlOutboxItem) error {
	return insertOutboxExec(context.Background(), tx, item)
}

func insertOutboxExec(ctx context.Context, exec sqlContextExecer, item ControlOutboxItem) error {
	ts := now()
	commandID := deterministicMessageID(item.OperationID, item.MessageType)
	resultID := deterministicMessageID(commandID, "operation_complete")
	controllerResultID := deterministicMessageID(item.OperationID, "operation_complete")
	if _, err := exec.ExecContext(ctx,
		`INSERT INTO control_outbox
		    (operation_id, message_type, node_id, semantic_payload, state,
		     attempt_count, created_at, updated_at, command_message_id,
		     operation_complete_message_id, controller_operation_complete_message_id)
		 VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?, ?)`,
		item.OperationID, item.MessageType, item.NodeID, item.SemanticPayload,
		ts, ts, commandID, resultID, controllerResultID,
	); err != nil {
		return fmt.Errorf("store: outbox insert: %w", err)
	}
	return nil
}
