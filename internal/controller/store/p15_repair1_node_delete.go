package store

// P15 repair-1 H3: store support for the durable node-deletion lifecycle and
// its App watcher. The API records a NodeDeletionOperation (the durable
// intent); force mode additionally invokes the P14 lifecycle tombstone/enqueue
// service. The watcher consumes correlated node_decommission_ack inbox rows and
// advances the operation to COMPLETED, confirming the force tombstone when one
// exists.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// CreateNodeDeletionOperation records the durable node-deletion operation row
// without enqueueing an outbox command. The force path uses this together with
// the P14 lifecycle (which creates the cleanup tombstone and enqueues the
// node_decommission command through the cleanup guard).
func (s *Store) CreateNodeDeletionOperation(op NodeDeletionOperation) error {
	if op.ID == "" || op.NodeID == "" || op.Status == "" || op.Mode == "" {
		return ErrTrafficInvalid
	}
	ts := s.currentUnix()
	_, err := s.db.Exec(
		`INSERT INTO node_deletion_operations (id, node_id, status, mode, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, op.Status, op.Mode, ts)
	if err != nil {
		return fmt.Errorf("store: create node deletion operation: %w", err)
	}
	op.CreatedAt = ts
	return nil
}

// DeleteNodeDeletionOperation removes a node-deletion operation row that was
// never observed by any consumer (repair-2 P2-A). It is used ONLY to roll back
// a stale force-delete intent whose terminal cleanup fact a concurrent delete
// won (ErrCleanupTombstoneConflict): the winner's operation stays the
// authority, so the loser's orphaned PENDING row must not linger pollable
// forever. It is intentionally not reachable from any frozen route.
func (s *Store) DeleteNodeDeletionOperation(id string) error {
	if id == "" {
		return ErrNotFound
	}
	res, err := s.db.Exec(`DELETE FROM node_deletion_operations WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete node deletion operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListNodeDeletionResults returns RECEIVED node_decommission_ack inbox rows that
// correlate to a live node_deletion_operations row, in durable inbox order.
// Rows belonging to other operations are never returned, so an unbounded
// non-deletion ack page cannot starve the watcher.
func (s *Store) ListNodeDeletionResults(limit int) ([]ControlInboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT i.id, i.message_id, i.node_id, i.message_type,
		        COALESCE(i.operation_id, ''), i.semantic_payload, i.state, i.updated_at
		   FROM control_inbox i
		   JOIN node_deletion_operations o ON o.id = i.operation_id
		  WHERE i.state = 'RECEIVED' AND i.message_type = 'node_decommission_ack'
		  ORDER BY i.id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list node deletion results: %w", err)
	}
	defer rows.Close()
	var items []ControlInboxItem
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.ID, &item.MessageID, &item.NodeID, &item.MessageType,
			&item.OperationID, &item.SemanticPayload, &item.State, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan node deletion result: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// nodeDecommissionAck is the minimal controller-side ACK identity mirror of
// the agent's DecommissionAck (never carries forward secrets).
type nodeDecommissionAck struct {
	NodeID      string `json:"node_id"`
	OperationID string `json:"decommission_operation_id"`
	Status      string `json:"status"`
	Force       bool   `json:"force,omitempty"`
}

// CompleteNodeDeletionResult atomically applies one durable node_decommission_ack:
// validates the message/operation/node binding, advances a PENDING node deletion
// operation to COMPLETED, confirms a force cleanup tombstone when the operation
// is force mode, and marks the inbox row PROCESSED. A correlated row whose
// operation is already COMPLETED is replayed idempotently (the inbox row is
// PROCESSED, no second side effect). The bool distinguishes "not a node
// deletion result" (false, nil) from success (true, err==nil).
func (s *Store) CompleteNodeDeletionResult(messageID string) (NodeDeletionOperation, bool, error) {
	if messageID == "" {
		return NodeDeletionOperation{}, false, ErrCASConflict
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return NodeDeletionOperation{}, false, fmt.Errorf("store: node deletion result conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return NodeDeletionOperation{}, false, fmt.Errorf("store: begin node deletion result: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var inboxNode, inboxType, inboxOperation, inboxPayload, inboxState string
	if err := conn.QueryRowContext(context.Background(),
		`SELECT node_id, message_type, COALESCE(operation_id, ''), semantic_payload, state
		   FROM control_inbox WHERE message_id = ?`, messageID).
		Scan(&inboxNode, &inboxType, &inboxOperation, &inboxPayload, &inboxState); errors.Is(err, sql.ErrNoRows) {
		return NodeDeletionOperation{}, false, ErrNotFound
	} else if err != nil {
		return NodeDeletionOperation{}, false, fmt.Errorf("store: read node deletion result inbox: %w", err)
	}
	if inboxType != "node_decommission_ack" {
		return NodeDeletionOperation{}, false, ErrNotFound
	}

	var op NodeDeletionOperation
	var completedAt sql.NullInt64
	err = conn.QueryRowContext(context.Background(),
		`SELECT id, node_id, status, mode, created_at, completed_at
		   FROM node_deletion_operations WHERE id = ?`, inboxOperation).
		Scan(&op.ID, &op.NodeID, &op.Status, &op.Mode, &op.CreatedAt, &completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Not a node-deletion result; leave the row for its own consumer.
		return NodeDeletionOperation{}, false, nil
	} else if err != nil {
		return NodeDeletionOperation{}, false, fmt.Errorf("store: resolve node deletion result: %w", err)
	}
	op.CompletedAt = completedAt.Int64

	var ack nodeDecommissionAck
	if err := json.Unmarshal([]byte(inboxPayload), &ack); err != nil || ack.NodeID == "" || ack.OperationID == "" {
		return NodeDeletionOperation{}, false, fmt.Errorf("%w: malformed node decommission ack %q", ErrPermanentDeletionResult, messageID)
	}
	if ack.NodeID != inboxNode || ack.OperationID != inboxOperation || ack.NodeID != op.NodeID || ack.OperationID != op.ID {
		return NodeDeletionOperation{}, false, fmt.Errorf("%w: node decommission ack binding mismatch %q", ErrPermanentDeletionResult, messageID)
	}
	if ack.Status != "DECOMMISSIONED" && ack.Status != "DROPPED_DUE_TO_DECOMMISSION" {
		return NodeDeletionOperation{}, false, fmt.Errorf("%w: unsupported node decommission ack status %q", ErrPermanentDeletionResult, ack.Status)
	}
	if ack.Force != (op.Mode == "force") {
		return NodeDeletionOperation{}, false, fmt.Errorf("%w: node decommission ack force mismatch %q", ErrPermanentDeletionResult, messageID)
	}

	switch op.Status {
	case "COMPLETED":
		// Idempotent replay: only the inbox disposition is advanced below.
	case "PENDING":
		res, err := conn.ExecContext(context.Background(),
			`UPDATE node_deletion_operations SET status = 'COMPLETED', completed_at = ?
			  WHERE id = ? AND node_id = ? AND status = 'PENDING'`,
			s.currentUnix(), op.ID, op.NodeID)
		if err != nil {
			return NodeDeletionOperation{}, false, fmt.Errorf("store: complete node deletion operation: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return NodeDeletionOperation{}, false, fmt.Errorf("store: complete node deletion rows: %w", err)
		} else if n != 1 {
			return NodeDeletionOperation{}, false, ErrCASConflict
		}
		op.Status = "COMPLETED"
		op.CompletedAt = s.currentUnix()
	default:
		return NodeDeletionOperation{}, false, fmt.Errorf("%w: node deletion operation is %s", ErrCASConflict, op.Status)
	}

	if op.Mode == "force" && ack.Status == "DECOMMISSIONED" {
		// A successful remote decommission is the only ACK that confirms the
		// force tombstone. DROPPED_DUE_TO_DECOMMISSION remains unconfirmed.
		if _, err := conn.ExecContext(context.Background(),
			`UPDATE node_cleanup_tombstones SET remote_cleanup_confirmed = 1, updated_at = ?
			  WHERE node_id = ?`, s.currentUnix(), op.NodeID); err != nil {
			return NodeDeletionOperation{}, false, fmt.Errorf("store: confirm node cleanup after delete: %w", err)
		}
	}

	if inboxState != ControlInboxProcessed {
		res, err := conn.ExecContext(context.Background(),
			`UPDATE control_inbox SET state = 'PROCESSED', updated_at = ?
			  WHERE message_id = ? AND state = 'RECEIVED'`, s.currentUnix(), messageID)
		if err != nil {
			return NodeDeletionOperation{}, false, fmt.Errorf("store: mark node deletion result processed: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return NodeDeletionOperation{}, false, fmt.Errorf("store: node deletion result processed rows: %w", err)
		} else if n != 1 {
			var current string
			_ = conn.QueryRowContext(context.Background(),
				`SELECT state FROM control_inbox WHERE message_id = ?`, messageID).Scan(&current)
			return NodeDeletionOperation{}, false, fmt.Errorf("%w: node deletion result inbox is %s", ErrCASConflict, current)
		}
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return NodeDeletionOperation{}, false, fmt.Errorf("store: commit node deletion result: %w", err)
	}
	committed = true
	return op, true, nil
}
