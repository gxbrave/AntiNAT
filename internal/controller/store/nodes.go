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

// ControlOwner is the immutable durable identity of one node control session.
// A session id alone is not sufficient fencing material: a reconnect may reuse
// application state while the node epoch has already advanced.
type ControlOwner struct {
	NodeID          string
	ConnectionEpoch uint64
	SessionID       string
}

// CreateNode inserts a new node. A node name is unique. Growth writes are
// refused under low-disk policy (delete paths are not).
func (s *Store) CreateNode(n Node) error {
	if err := s.checkWriteCapacity(); err != nil {
		return err
	}
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

// RequireCurrentControlOwner verifies that owner is still the node's durable
// connection owner. It is a cheap frame-time fence; owner-aware mutations also
// repeat the predicate in their SQL so a takeover cannot race the write.
func (s *Store) RequireCurrentControlOwner(owner ControlOwner) error {
	if owner.NodeID == "" || owner.SessionID == "" || owner.ConnectionEpoch == 0 {
		return fmt.Errorf("%w: incomplete control owner", ErrStaleControlOwner)
	}
	var matched int
	err := s.db.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM nodes
		 WHERE id = ? AND current_connection_epoch = ? AND current_session_id = ?
	)`, owner.NodeID, owner.ConnectionEpoch, owner.SessionID).Scan(&matched)
	if err != nil {
		return fmt.Errorf("store: check control owner: %w", err)
	}
	if matched != 1 {
		return fmt.Errorf("%w: node %q owner is no longer current", ErrStaleControlOwner, owner.NodeID)
	}
	return nil
}

// AcquireControlOwner advances the connection epoch/session atomically only
// when the expected epoch matches, returning the exact owner tuple that must
// fence every subsequent live-session mutation.
func (s *Store) AcquireControlOwner(id string, expectedEpoch uint64, newSessionID string) (ControlOwner, error) {
	res, err := s.db.Exec(
		`UPDATE nodes
		    SET current_connection_epoch = current_connection_epoch + 1,
		        current_session_id = ?, revision = revision + 1, updated_at = ?
		  WHERE id = ? AND current_connection_epoch = ?`,
		newSessionID, now(), id, expectedEpoch,
	)
	if err != nil {
		return ControlOwner{}, fmt.Errorf("store: CAS node epoch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ControlOwner{}, fmt.Errorf("store: CAS node epoch rows: %w", err)
	}
	if n != 1 {
		return ControlOwner{}, ErrCASConflict
	}
	return ControlOwner{NodeID: id, ConnectionEpoch: expectedEpoch + 1, SessionID: newSessionID}, nil
}

// CASNodeConnectionEpoch is the compatibility wrapper for callers that only
// need the success/error result. New live-session code should retain the
// returned ControlOwner and use owner-aware mutations.
func (s *Store) CASNodeConnectionEpoch(id string, expectedEpoch uint64, newSessionID string) error {
	_, err := s.AcquireControlOwner(id, expectedEpoch, newSessionID)
	return err
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
