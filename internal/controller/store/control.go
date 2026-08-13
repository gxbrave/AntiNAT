package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// P08-owned store extension: the controller-side control FSM methods. P06
// created the control_outbox/control_inbox tables and the enqueue/count/get
// surface; the per-session claim/send/ack/receipt transitions and the inbox
// dedup are the P08-declared additions consumed by the agent hub (frozen
// state-model §3.1, protocol.md §3.5).

// Control-plane FSM sentinels mirroring the agent journal semantics.
var (
	// ErrIllegalPhase rejects an FSM transition that is not the exact
	// predecessor single step.
	ErrIllegalPhase = errors.New("store: illegal control outbox phase transition")
	// ErrStaleSession rejects a transition from a session that is not the
	// row's binding session (old-epoch ACK rejection).
	ErrStaleSession = errors.New("store: control transition from a stale session")
	// ErrMessageConflict rejects a duplicate message_id with different type
	// or payload (fail-closed session conflict, protocol.md §3.5).
	ErrMessageConflict = errors.New("store: control inbox message id conflict")
)

// ControlInboxItem is one durable inbound A2C message record.
type ControlInboxItem struct {
	MessageID       string
	NodeID          string
	MessageType     string
	OperationID     string
	SemanticPayload string
	State           string
}

// ClaimControlOutbox atomically advances up to limit PENDING rows for a node
// to CLAIMED bound to the session and returns the claimed items in id order.
func (s *Store) ClaimControlOutbox(nodeID, sessionID string, limit int) ([]ControlOutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin outbox claim: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, operation_id, message_type, node_id, semantic_payload, state
		   FROM control_outbox
		  WHERE node_id = ? AND state = 'PENDING'
		  ORDER BY id ASC LIMIT ?`, nodeID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: query pending outbox: %w", err)
	}
	var items []ControlOutboxItem
	var ids []int64
	for rows.Next() {
		var item ControlOutboxItem
		var id int64
		if err := rows.Scan(&id, &item.OperationID, &item.MessageType, &item.NodeID,
			&item.SemanticPayload, &item.State); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan pending outbox: %w", err)
		}
		items = append(items, item)
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: pending outbox rows: %w", err)
	}
	for _, id := range ids {
		if _, err := tx.Exec(
			`UPDATE control_outbox SET state = 'CLAIMED', session_id = ?, updated_at = ?
			  WHERE id = ? AND state = 'PENDING'`,
			sessionID, now(), id,
		); err != nil {
			return nil, fmt.Errorf("store: claim outbox row: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit outbox claim: %w", err)
	}
	for i := range items {
		items[i].State = "CLAIMED"
	}
	return items, nil
}

// outboxTransition applies a single-step FSM transition to the row identified
// by (operation_id, message_type), verifying the session binding.
func (s *Store) outboxTransition(operationID, messageType, sessionID, want, next string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox
		    SET state = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = ?`,
		next, now(), operationID, messageType, want,
	)
	if err != nil {
		return fmt.Errorf("store: outbox transition %s->%s: %w", want, next, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: outbox transition rows: %w", err)
	}
	if n == 0 {
		// Distinguish stale session from illegal phase.
		var session string
		err := s.db.QueryRow(
			`SELECT session_id FROM control_outbox
			  WHERE operation_id = ? AND message_type = ?`,
			operationID, messageType,
		).Scan(&session)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
		}
		if err != nil {
			return err
		}
		if session != sessionID {
			return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, session)
		}
		return fmt.Errorf("%w: operation %q is not %s", ErrIllegalPhase, operationID, want)
	}
	return nil
}

// MarkControlOutboxSent advances CLAIMED -> SENT (socket write done).
func (s *Store) MarkControlOutboxSent(operationID, messageType, sessionID string) error {
	// Verify session binding first: the transition must not advance a row
	// claimed by another session.
	var bound string
	err := s.db.QueryRow(
		`SELECT session_id FROM control_outbox
		  WHERE operation_id = ? AND message_type = ?`, operationID, messageType,
	).Scan(&bound)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
	}
	if err != nil {
		return err
	}
	if bound != sessionID {
		return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, bound)
	}
	return s.outboxTransition(operationID, messageType, sessionID, "CLAIMED", "SENT")
}

// AcceptControlSemanticACK advances SENT -> SEMANTIC_ACKED. A semantic ACK
// never permits GC.
func (s *Store) AcceptControlSemanticACK(operationID, messageType, sessionID string) error {
	return s.outboxTransition(operationID, messageType, sessionID, "SENT", "SEMANTIC_ACKED")
}

// AcceptControlReceipt advances SEMANTIC_ACKED -> RECEIPTED and GCs the row
// (the durable receipt is recorded in control_inbox; the outbox row is
// deleted so the outbox stays bounded).
func (s *Store) AcceptControlReceipt(operationID, messageType, sessionID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin outbox receipt: %w", err)
	}
	defer tx.Rollback()

	var state, session string
	err = tx.QueryRow(
		`SELECT state, session_id FROM control_outbox
		  WHERE operation_id = ? AND message_type = ?`, operationID, messageType,
	).Scan(&state, &session)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
	}
	if err != nil {
		return err
	}
	if session != sessionID {
		return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, session)
	}
	if state != "SEMANTIC_ACKED" {
		return fmt.Errorf("%w: operation %q is %s, want SEMANTIC_ACKED", ErrIllegalPhase, operationID, state)
	}
	if _, err := tx.Exec(
		`UPDATE control_outbox SET state = 'RECEIPTED', updated_at = ? WHERE operation_id = ? AND message_type = ?`,
		now(), operationID, messageType,
	); err != nil {
		return fmt.Errorf("store: mark outbox receipted: %w", err)
	}
	// GC: the outbox row is removed; the durable record lives in control_inbox.
	if _, err := tx.Exec(
		`DELETE FROM control_outbox WHERE operation_id = ? AND message_type = ?`,
		operationID, messageType,
	); err != nil {
		return fmt.Errorf("store: gc outbox row: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit outbox receipt: %w", err)
	}
	return nil
}

// RequeueControlOutboxForSession resets every in-flight row of the node to
// PENDING so a new session re-envelopes the same semantic payload (v0.8
// §6.1). Only CLAIMED/SENT rows are requeued: a SEMANTIC_ACKED row is the
// controller's own proof that the agent's result was already processed and
// the C2A receipt written, so re-delivering it could hand the agent a
// command it has already durably receipted (journal tombstone fails closed
// with ErrAlreadyReceipted and kills the session). SEMANTIC_ACKED rows are
// healed by the result-resend path (RebindControlOutboxSession) or, for
// rows whose A2C receipt was lost, left for the receipt-TTL sweeper (P14
// lifecycle scope). Returns the number of rows requeued.
func (s *Store) RequeueControlOutboxForSession(nodeID, sessionID string) (int, error) {
	res, err := s.db.Exec(
		`UPDATE control_outbox
		    SET state = 'PENDING', session_id = ?, updated_at = ?
		  WHERE node_id = ? AND state IN ('CLAIMED', 'SENT')`,
		sessionID, now(), nodeID,
	)
	if err != nil {
		return 0, fmt.Errorf("store: requeue outbox for session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: requeue outbox rows: %w", err)
	}
	return int(n), nil
}

// RebindControlOutboxSession re-binds a SEMANTIC_ACKED row to the session
// that resends its result. The authenticated, deduped result resend proves
// the new session is continuing the operation, so the follow-up A2C receipt
// from that session may complete the GC; without the re-bind the receipt
// would be rejected as stale-session and kill the session. The FSM state is
// untouched (no advance past SEMANTIC_ACKED); any other state fails closed.
func (s *Store) RebindControlOutboxSession(operationID, messageType, sessionID string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox SET session_id = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = 'SEMANTIC_ACKED'`,
		sessionID, now(), operationID, messageType,
	)
	if err != nil {
		return fmt.Errorf("store: rebind outbox session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rebind outbox rows: %w", err)
	}
	if n == 0 {
		var state string
		err := s.db.QueryRow(
			`SELECT state FROM control_outbox
			  WHERE operation_id = ? AND message_type = ?`,
			operationID, messageType,
		).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: operation %q is %s, want SEMANTIC_ACKED", ErrIllegalPhase, operationID, state)
	}
	return nil
}

// RecordControlInbox durably records an inbound A2C message. message_id is
// UNIQUE (protocol.md §3.5): the same id + same type + same payload is a
// cached duplicate (returned true); the same id with different type or
// payload is a fail-closed conflict.
func (s *Store) RecordControlInbox(item ControlInboxItem) (bool, error) {
	var existingMessageType, existingPayload string
	err := s.db.QueryRow(
		`SELECT message_type, semantic_payload FROM control_inbox WHERE message_id = ?`,
		item.MessageID,
	).Scan(&existingMessageType, &existingPayload)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.Exec(
			`INSERT INTO control_inbox
			    (message_id, node_id, message_type, semantic_payload, state,
			     operation_id, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 'RECEIVED', ?, ?, ?)`,
			item.MessageID, item.NodeID, item.MessageType, item.SemanticPayload,
			item.OperationID, now(), now(),
		); err != nil {
			return false, fmt.Errorf("store: record control inbox: %w", err)
		}
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store: get control inbox: %w", err)
	case existingMessageType != item.MessageType || existingPayload != item.SemanticPayload:
		return false, fmt.Errorf("%w: message %q (type=%s) vs persisted (type=%s)", ErrMessageConflict, item.MessageID, item.MessageType, existingMessageType)
	default:
		return true, nil
	}
}

// ClaimControlOutboxOperation claims ONE pending row for a session (used when
// a result arrives before the pump re-claimed a requeued row on reconnect).
func (s *Store) ClaimControlOutboxOperation(operationID, messageType, sessionID string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox SET state = 'CLAIMED', session_id = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = 'PENDING'`,
		sessionID, now(), operationID, messageType,
	)
	if err != nil {
		return fmt.Errorf("store: claim outbox operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: claim outbox operation rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: operation %q is not PENDING", ErrIllegalPhase, operationID)
	}
	return nil
}

// ListControlOutboxByState returns the node's outbox rows in the given
// states (used to correlate inbound results/receipts to in-flight rows).
func (s *Store) ListControlOutboxByState(nodeID string, states ...string) ([]ControlOutboxItem, error) {
	if len(states) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(states))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(states)+1)
	args = append(args, nodeID)
	for _, st := range states {
		args = append(args, st)
	}
	rows, err := s.db.Query(
		`SELECT operation_id, message_type, node_id, semantic_payload, state
		   FROM control_outbox WHERE node_id = ? AND state IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list control outbox: %w", err)
	}
	defer rows.Close()
	var items []ControlOutboxItem
	for rows.Next() {
		var item ControlOutboxItem
		if err := rows.Scan(&item.OperationID, &item.MessageType, &item.NodeID,
			&item.SemanticPayload, &item.State); err != nil {
			return nil, fmt.Errorf("store: scan control outbox: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// SetNodeControlState updates the node's control_state (ONLINE/OFFLINE).
func (s *Store) SetNodeControlState(nodeID, state string) error {
	res, err := s.db.Exec(
		`UPDATE nodes SET control_state = ?, updated_at = ? WHERE id = ?`,
		state, now(), nodeID,
	)
	if err != nil {
		return fmt.Errorf("store: set node control state: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set node control state rows: %w", err)
	} else if n != 1 {
		return ErrNodeNotFound
	}
	return nil
}
