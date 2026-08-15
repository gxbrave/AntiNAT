package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// P10-owned store extension: list/query surface for the minimal admin API
// (Story 4). The frozen schema is unchanged; these are read helpers over the
// existing tables plus the atomic forward-create-with-desired transaction.

// ErrForwardNameConflict identifies the stable (node_id, name) uniqueness
// conflict separately from infrastructure/transaction failures.
var ErrForwardNameConflict = errors.New("store: forward name already exists on node")

// CreateForwardBundle atomically persists a Forward, its initial desired spec,
// its desired-state outbox command, and the idempotency response. The
// idempotency lookup and all inserts run under BEGIN IMMEDIATE so concurrent
// controller processes cannot both pass a read-before-write check. A replay
// returns the original response without touching any forward-side rows.
func (s *Store) CreateForwardBundle(ctx context.Context, f Forward, spec ForwardSpec, outbox ControlOutboxItem, rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	if f.ID == "" || spec.ForwardID != f.ID || outbox.NodeID != f.NodeID {
		return IdempotencyRecord{}, false, errors.New("store: forward bundle identity mismatch")
	}
	if err := s.checkWriteCapacity(); err != nil {
		return IdempotencyRecord{}, false, err
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: begin forward bundle: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	ts := now()
	expires := rec.ExpiresAt
	if expires == 0 {
		expires = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	rec.CreatedAt = ts
	rec.ExpiresAt = expires

	var existing IdempotencyRecord
	err = conn.QueryRowContext(ctx,
		`SELECT key, route, principal, request_hash, response_status,
		        response_body, created_at, expires_at
		   FROM api_idempotency_keys WHERE key = ?`, rec.Key,
	).Scan(&existing.Key, &existing.Route, &existing.Principal, &existing.RequestHash,
		&existing.ResponseStatus, &existing.ResponseBody, &existing.CreatedAt, &existing.ExpiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// New key: continue with the forward-side writes below.
	case err != nil:
		return IdempotencyRecord{}, false, fmt.Errorf("store: get forward idempotency: %w", err)
	case existing.ExpiresAt > ts:
		if existing.Route != rec.Route || existing.Principal != rec.Principal || existing.RequestHash != rec.RequestHash {
			return IdempotencyRecord{}, false, ErrIdempotencyConflict
		}
		return existing, true, nil
	default:
		// Expired keys are replaced only if the complete forward bundle commits;
		// the audit row and delete therefore remain inside this transaction.
		if _, err := conn.ExecContext(ctx, `DELETE FROM api_idempotency_keys WHERE key = ?`, rec.Key); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: expire forward idempotency delete: %w", err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"IDEMPOTENCY_KEY_EXPIRED",
			fmt.Sprintf(`{"key":%q,"route":%q}`, rec.Key, rec.Route), ts); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: forward idempotency expiry audit: %w", err)
		}
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO forwards (id, node_id, name, protocol, current_activation_id,
		                       revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.NodeID, f.Name, f.Protocol, f.CurrentActivationID, f.Revision, ts, ts); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: forwards.node_id, forwards.name") {
			return IdempotencyRecord{}, false, fmt.Errorf("%w: %v", ErrForwardNameConflict, err)
		}
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle forward insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO forward_specs (id, forward_id, revision, spec_json, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		spec.ID, spec.ForwardID, spec.Revision, spec.SpecJSON, ts); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle spec insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO control_outbox
		    (operation_id, message_type, node_id, semantic_payload, state,
		     attempt_count, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		outbox.OperationID, outbox.MessageType, outbox.NodeID, outbox.SemanticPayload,
		orDefault(outbox.State, "PENDING"), ts, ts); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle outbox insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO api_idempotency_keys
		    (key, route, principal, request_hash, response_status,
		     response_body, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Key, rec.Route, rec.Principal, rec.RequestHash, rec.ResponseStatus,
		rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle idempotency insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: commit forward bundle: %w", err)
	}
	committed = true
	return rec, false, nil
}

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
