package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// ControlOutboxItem is a semantic control-outbox entry (frozen state-model
// §3.1). The outbox stores the semantic payload, never a signed frame from an
// old session; the same operation/message ID is re-enveloped on reconnect.
type ControlOutboxItem struct {
	OperationID     string
	MessageType     string
	NodeID          string
	SemanticPayload string
	State           string
}

// EnqueueControlOutbox inserts a PENDING outbox item. The caller-supplied
// State is intentionally ignored: a new intent cannot bypass delivery and
// receipt fencing by manufacturing a later FSM phase. (operation_id,
// message_type) is unique, so re-enqueueing the same operation faults —
// callers use the transactional Apply* methods to pair an operation with its
// outbox entry atomically.
func (s *Store) EnqueueControlOutbox(item ControlOutboxItem) error {
	ts := now()
	_, err := s.db.Exec(
		`INSERT INTO control_outbox
		    (operation_id, message_type, node_id, semantic_payload, state,
		     attempt_count, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)`,
		item.OperationID, item.MessageType, item.NodeID, item.SemanticPayload,
		ts, ts,
	)
	if err != nil {
		return fmt.Errorf("store: enqueue control outbox: %w", err)
	}
	return nil
}

// ControlOutboxCount returns the number of outbox items for a node.
func (s *Store) ControlOutboxCount(nodeID string) (int, error) {
	var count int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM control_outbox WHERE node_id = ?", nodeID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count control outbox: %w", err)
	}
	return count, nil
}

// ControlOutboxItemByOperation returns the outbox row for an operation/message
// pair, for receipt-driven state transitions.
func (s *Store) ControlOutboxItemByOperation(operationID, messageType string) (ControlOutboxItem, error) {
	var item ControlOutboxItem
	err := s.db.QueryRow(
		`SELECT operation_id, message_type, node_id, semantic_payload, state
		   FROM control_outbox WHERE operation_id = ? AND message_type = ?`,
		operationID, messageType,
	).Scan(&item.OperationID, &item.MessageType, &item.NodeID, &item.SemanticPayload, &item.State)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlOutboxItem{}, ErrNotFound
	}
	if err != nil {
		return ControlOutboxItem{}, fmt.Errorf("store: get control outbox item: %w", err)
	}
	return item, nil
}
