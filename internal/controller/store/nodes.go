package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Node is a Controller control-plane node row. CurrentConnectionEpoch and
// CurrentSessionID are the two-way connection epoch fencing columns (frozen
// state-model §6.3); they are mutated only through CAS methods.
type Node struct {
	ID                     string
	Name                   string
	CurrentConnectionEpoch uint64
	CurrentSessionID       string
	ControlState           string
	Revision               uint64
	CreatedAt              int64
	UpdatedAt              int64
}

// CreateNode inserts a new node. A node name is unique.
func (s *Store) CreateNode(n Node) error {
	ts := now()
	_, err := s.db.Exec(
		`INSERT INTO nodes (id, name, current_connection_epoch, current_session_id,
		                    control_state, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.Name, n.CurrentConnectionEpoch, n.CurrentSessionID,
		orDefault(n.ControlState, "OFFLINE"), n.Revision, ts, ts,
	)
	if err != nil {
		return fmt.Errorf("store: create node: %w", err)
	}
	return nil
}

// GetNode returns a node by ID.
func (s *Store) GetNode(id string) (Node, error) {
	var n Node
	err := s.db.QueryRow(
		`SELECT id, name, current_connection_epoch, current_session_id,
		        control_state, revision, created_at, updated_at
		   FROM nodes WHERE id = ?`, id,
	).Scan(&n.ID, &n.Name, &n.CurrentConnectionEpoch, &n.CurrentSessionID,
		&n.ControlState, &n.Revision, &n.CreatedAt, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNodeNotFound
	}
	if err != nil {
		return Node{}, fmt.Errorf("store: get node: %w", err)
	}
	return n, nil
}

// CASNodeConnectionEpoch advances the connection epoch/session atomically only
// when the expected epoch matches. It returns ErrCASConflict on a stale write.
func (s *Store) CASNodeConnectionEpoch(id string, expectedEpoch uint64, newSessionID string) error {
	res, err := s.db.Exec(
		`UPDATE nodes
		    SET current_connection_epoch = current_connection_epoch + 1,
		        current_session_id = ?, revision = revision + 1, updated_at = ?
		  WHERE id = ? AND current_connection_epoch = ?`,
		newSessionID, now(), id, expectedEpoch,
	)
	if err != nil {
		return fmt.Errorf("store: CAS node epoch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: CAS node epoch rows: %w", err)
	}
	if n != 1 {
		return ErrCASConflict
	}
	return nil
}

// NodeDeletionOperation is a durable node deletion/decommission record. It is
// independent of the node row lifecycle (frozen state-model §4). Mode is
// 'normal' or 'force'.
type NodeDeletionOperation struct {
	ID          string
	NodeID      string
	Status      string
	Mode        string
	CreatedAt   int64
	CompletedAt int64
}

// GetNodeDeletionOperation returns a node deletion operation by ID.
func (s *Store) GetNodeDeletionOperation(id string) (NodeDeletionOperation, error) {
	var op NodeDeletionOperation
	var completedAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT id, node_id, status, mode, created_at, completed_at
		   FROM node_deletion_operations WHERE id = ?`, id,
	).Scan(&op.ID, &op.NodeID, &op.Status, &op.Mode, &op.CreatedAt, &completedAt)
	op.CompletedAt = completedAt.Int64
	if errors.Is(err, sql.ErrNoRows) {
		return NodeDeletionOperation{}, ErrNotFound
	}
	if err != nil {
		return NodeDeletionOperation{}, fmt.Errorf("store: get node deletion operation: %w", err)
	}
	return op, nil
}
