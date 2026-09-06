package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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
	// RetryAfterUnix is the earliest unix second the row may be claimed again
	// after a delivery-time gate refused it (repair-2 L-B bounded backoff). 0
	// means immediately claimable.
	RetryAfterUnix int64
}

// EnqueueControlOutbox inserts a PENDING outbox item. The caller-supplied
// State is intentionally ignored: a new intent cannot bypass delivery and
// receipt fencing by manufacturing a later FSM phase. (operation_id,
// message_type) is unique, so re-enqueueing the same operation faults —
// callers use the transactional Apply* methods to pair an operation with its
// outbox entry atomically.
func (s *Store) EnqueueControlOutbox(item ControlOutboxItem) error {
	// P14 Story 3: a cleanup-only (force-deleted) node must never receive new
	// desired/secrets/rotation material. The enqueue guard is the durable
	// issuance barrier; the session-level gate covers already-enqueued rows.
	if err := s.EnforceCleanupOnlyEnqueue(item.NodeID, item.MessageType, nil); err != nil {
		return err
	}
	ts := now()
	commandID := deterministicMessageID(item.OperationID, item.MessageType)
	resultID := deterministicMessageID(commandID, "operation_complete")
	controllerResultID := deterministicMessageID(item.OperationID, "operation_complete")
	_, err := s.db.Exec(
		`INSERT INTO control_outbox
		    (operation_id, message_type, node_id, semantic_payload, state,
		     attempt_count, created_at, updated_at, command_message_id,
		     operation_complete_message_id, controller_operation_complete_message_id)
		 VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?, ?)`,
		item.OperationID, item.MessageType, item.NodeID, item.SemanticPayload,
		ts, ts, commandID, resultID, controllerResultID,
	)
	if err != nil {
		return fmt.Errorf("store: enqueue control outbox: %w", err)
	}
	return nil
}

// deterministicMessageID mirrors security.MessageID without coupling the
// storage package to the transport package. These values are persisted so
// correlation can use an indexed equality lookup after restart.
func deterministicMessageID(operationID, messageType string) string {
	sum := sha256.Sum256([]byte("antinat-msgid-v1\x00" + operationID + "\x00" + messageType))
	return hex.EncodeToString(sum[:16])
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

// ControlOutboxItemByCorrelation performs an indexed equality lookup for a
// deterministic command or operation-complete message id. It never scans the
// bounded delivery window, so a live row beyond that window remains visible.
func (s *Store) ControlOutboxItemByCorrelation(nodeID, messageID, correlation string, states ...string) (ControlOutboxItem, error) {
	if correlation != "command" && correlation != "operation_complete" && correlation != "controller_operation_complete" {
		return ControlOutboxItem{}, fmt.Errorf("store: unknown outbox correlation %q", correlation)
	}
	if len(states) == 0 {
		return ControlOutboxItem{}, ErrNotFound
	}
	placeholders := strings.Repeat("?,", len(states))
	placeholders = placeholders[:len(placeholders)-1]
	column := "command_message_id"
	if correlation == "operation_complete" {
		column = "operation_complete_message_id"
	} else if correlation == "controller_operation_complete" {
		column = "controller_operation_complete_message_id"
	}
	args := make([]any, 0, len(states)+2)
	args = append(args, nodeID, messageID)
	for _, state := range states {
		args = append(args, state)
	}
	var item ControlOutboxItem
	err := s.db.QueryRow(
		`SELECT operation_id, message_type, node_id, semantic_payload, state, retry_after_unix
		   FROM control_outbox WHERE node_id = ? AND `+column+` = ?
		     AND state IN (`+placeholders+`) LIMIT 1`, args...,
	).Scan(&item.OperationID, &item.MessageType, &item.NodeID, &item.SemanticPayload, &item.State, &item.RetryAfterUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlOutboxItem{}, ErrNotFound
	}
	if err != nil {
		return ControlOutboxItem{}, fmt.Errorf("store: get correlated control outbox item: %w", err)
	}
	return item, nil
}

// ControlOutboxItemByOperation returns the outbox row for an operation/message
// pair, for receipt-driven state transitions.
func (s *Store) ControlOutboxItemByOperation(operationID, messageType string) (ControlOutboxItem, error) {
	var item ControlOutboxItem
	err := s.db.QueryRow(
		`SELECT operation_id, message_type, node_id, semantic_payload, state, retry_after_unix
		   FROM control_outbox WHERE operation_id = ? AND message_type = ?`,
		operationID, messageType,
	).Scan(&item.OperationID, &item.MessageType, &item.NodeID, &item.SemanticPayload, &item.State, &item.RetryAfterUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlOutboxItem{}, ErrNotFound
	}
	if err != nil {
		return ControlOutboxItem{}, fmt.Errorf("store: get control outbox item: %w", err)
	}
	return item, nil
}
