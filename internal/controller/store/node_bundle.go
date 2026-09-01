package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CreateNodeBundle atomically commits a node create and its idempotency
// response. BEGIN IMMEDIATE makes same-key callers observe one winner and
// replay its exact response; a persistence failure rolls back both records.
func (s *Store) CreateNodeBundle(ctx context.Context, n Node, rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	if err := s.checkWriteCapacity(); err != nil {
		return IdempotencyRecord{}, false, err
	}
	ts := now()
	if rec.ResponseStatus == 0 {
		rec.ResponseStatus = 201
	}
	if rec.ExpiresAt == 0 {
		rec.ExpiresAt = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	if rec.ResponseBody == "" {
		body, err := json.Marshal(struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			ControlState string `json:"control_state"`
			CreatedAt    string `json:"created_at"`
			ETag         string `json:"etag"`
		}{
			ID: n.ID, Name: n.Name, ControlState: orDefault(n.ControlState, "OFFLINE"),
			CreatedAt: time.Unix(ts, 0).UTC().Format(time.RFC3339), ETag: fmt.Sprintf("\"rev-%d\"", n.Revision),
		})
		if err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: marshal node bundle response: %w", err)
		}
		rec.ResponseBody = string(body)
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: node bundle conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: begin node bundle: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var existing IdempotencyRecord
	err = conn.QueryRowContext(ctx,
		`SELECT key, route, principal, request_hash, response_status,
		        response_body, created_at, expires_at
		   FROM api_idempotency_keys WHERE key = ?`, rec.Key,
	).Scan(&existing.Key, &existing.Route, &existing.Principal, &existing.RequestHash,
		&existing.ResponseStatus, &existing.ResponseBody, &existing.CreatedAt, &existing.ExpiresAt)
	switch {
	case err == nil && existing.ExpiresAt > ts && existing.Route == rec.Route &&
		existing.Principal == rec.Principal && existing.RequestHash == rec.RequestHash:
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: commit node replay: %w", err)
		}
		committed = true
		return existing, true, nil
	case err == nil && existing.ExpiresAt > ts:
		return IdempotencyRecord{}, false, ErrIdempotencyConflict
	case err == nil:
		if _, err := conn.ExecContext(ctx, `DELETE FROM api_idempotency_keys WHERE key = ?`, rec.Key); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: expire node idempotency: %w", err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"IDEMPOTENCY_KEY_EXPIRED", fmt.Sprintf(`{"key":%q,"route":%q}`, rec.Key, rec.Route), ts); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: node idempotency expiry audit: %w", err)
		}
	case !errors.Is(err, sql.ErrNoRows):
		return IdempotencyRecord{}, false, fmt.Errorf("store: read node idempotency: %w", err)
	}

	rec.CreatedAt = ts
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO nodes (id, name, current_connection_epoch, current_session_id,
		                    control_state, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.Name, n.CurrentConnectionEpoch, n.CurrentSessionID,
		orDefault(n.ControlState, "OFFLINE"), n.Revision, ts, ts); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: node bundle node insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO api_idempotency_keys
		    (key, route, principal, request_hash, response_status,
		     response_body, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Key, rec.Route, rec.Principal, rec.RequestHash, rec.ResponseStatus,
		rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: node bundle idempotency insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: commit node bundle: %w", err)
	}
	committed = true
	return rec, false, nil
}
