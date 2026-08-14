package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// P10-owned store extension: list/query surface for the minimal admin API
// (Story 4). The frozen schema is unchanged; these are read helpers over the
// existing tables plus the atomic forward-create-with-desired transaction.

// ListNodes returns every node in id order.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(
		`SELECT id, name, current_connection_epoch, current_session_id,
		        control_state, revision, created_at, updated_at
		   FROM nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.CurrentConnectionEpoch, &n.CurrentSessionID,
			&n.ControlState, &n.Revision, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ListForwards returns every forward in id order.
func (s *Store) ListForwards() ([]Forward, error) {
	rows, err := s.db.Query(
		`SELECT id, node_id, name, protocol, current_activation_id,
		        revision, created_at, updated_at
		   FROM forwards ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list forwards: %w", err)
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		if err := rows.Scan(&f.ID, &f.NodeID, &f.Name, &f.Protocol, &f.CurrentActivationID,
			&f.Revision, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan forward: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LatestForwardSpec returns the highest-revision spec of a forward.
func (s *Store) LatestForwardSpec(forwardID string) (ForwardSpec, error) {
	var spec ForwardSpec
	err := s.db.QueryRow(
		`SELECT id, forward_id, revision, spec_json, created_at
		   FROM forward_specs WHERE forward_id = ? ORDER BY revision DESC LIMIT 1`,
		forwardID,
	).Scan(&spec.ID, &spec.ForwardID, &spec.Revision, &spec.SpecJSON, &spec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwardSpec{}, ErrNotFound
	}
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("store: latest forward spec: %w", err)
	}
	return spec, nil
}

// CompleteForwardDeletionOperation marks a deletion operation completed.
func (s *Store) CompleteForwardDeletionOperation(id string) error {
	res, err := s.db.Exec(
		`UPDATE forward_deletion_operations SET status = 'COMPLETED', completed_at = ? WHERE id = ?`,
		now(), id,
	)
	if err != nil {
		return fmt.Errorf("store: complete forward deletion operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: complete forward deletion rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// ListControlInboxByType returns the durable inbound A2C records of the
// given message types, newest first (bounded). Used by the controller app
// watcher to complete forward-deletion operations when the agent's delete
// result arrives (P10 Story 6 online delete).
func (s *Store) ListControlInboxByType(nodeID string, types ...string) ([]ControlInboxItem, error) {
	if len(types) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(types))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(types)+1)
	for _, t := range types {
		args = append(args, t)
	}
	if nodeID != "" {
		args = append(args, nodeID)
	}
	where := "message_type IN (" + placeholders + ")"
	if nodeID != "" {
		where += " AND node_id = ?"
	}
	rows, err := s.db.Query(
		`SELECT message_id, node_id, message_type, operation_id, semantic_payload, state
		   FROM control_inbox WHERE `+where+` ORDER BY id DESC LIMIT 500`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list control inbox: %w", err)
	}
	defer rows.Close()
	var items []ControlInboxItem
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.MessageID, &item.NodeID, &item.MessageType,
			&item.OperationID, &item.SemanticPayload, &item.State); err != nil {
			return nil, fmt.Errorf("store: scan control inbox: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// CountEnrollmentTokens returns the number of enrollment token rows (the
// API uses it to verify token issuance is hash-only and single-use).
func (s *Store) CountEnrollmentTokens() (int, error) {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM node_enrollment_tokens").Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count enrollment tokens: %w", err)
	}
	return count, nil
}
