package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// IdempotencyKeyTTL is the frozen lifetime of a durable idempotency key
// (docs/error-codes.md §4). A key past this TTL may be reused by a new
// request, and the expiry is recorded as an audit event.
const IdempotencyKeyTTL = 24 * time.Hour

// ErrIdempotencyConflict is returned when an Idempotency-Key is reused with a
// different request hash (409 IDEMPOTENCY_CONFLICT in the API layer).
var ErrIdempotencyConflict = errors.New("store: idempotency key reused with a different request")

// IdempotencyRecord is a durable create-result record binding the key to its
// route, principal, request hash and stored response.
type IdempotencyRecord struct {
	Key            string
	Route          string
	Principal      string
	RequestHash    string
	ResponseStatus int
	ResponseBody   string
	CreatedAt      int64
	ExpiresAt      int64
}

// StoreIdempotency stores a result under a key. It returns the effective
// stored record and whether the caller should replay it:
//
//   - no prior row -> insert and return replayed=false;
//   - matching key + hash (unexpired) -> return stored row and replayed=true;
//   - matching key + different hash (unexpired) -> ErrIdempotencyConflict;
//   - expired row -> replace the row and emit an IDEMPOTENCY_KEY_EXPIRED
//     admin event in the same transaction, return replayed=false.
func (s *Store) StoreIdempotency(rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	ts := now()
	expires := rec.ExpiresAt
	if expires == 0 {
		expires = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	rec.ExpiresAt = expires

	existing, err := s.GetIdempotency(rec.Key)
	if errors.Is(err, ErrNotFound) {
		rec.CreatedAt = ts
		if _, err := s.db.Exec(
			`INSERT INTO api_idempotency_keys
			    (key, route, principal, request_hash, response_status,
			     response_body, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.Key, rec.Route, rec.Principal, rec.RequestHash,
			rec.ResponseStatus, rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: insert idempotency: %w", err)
		}
		return rec, false, nil
	}
	if err != nil {
		return IdempotencyRecord{}, false, err
	}

	switch {
	case existing.ExpiresAt > ts && existing.RequestHash == rec.RequestHash:
		return existing, true, nil
	case existing.ExpiresAt > ts:
		return IdempotencyRecord{}, false, ErrIdempotencyConflict
	default:
		// Expired: reuse the key for the new request, recording the expiry.
		tx, err := s.db.Begin()
		if err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: begin idempotency reuse: %w", err)
		}
		defer tx.Rollback()
		rec.CreatedAt = ts
		if _, err := tx.Exec(`DELETE FROM api_idempotency_keys WHERE key = ?`, rec.Key); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: expire idempotency delete: %w", err)
		}
		if _, err := tx.Exec(
			`INSERT INTO api_idempotency_keys
			    (key, route, principal, request_hash, response_status,
			     response_body, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.Key, rec.Route, rec.Principal, rec.RequestHash,
			rec.ResponseStatus, rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: idempotency reuse insert: %w", err)
		}
		if _, err := tx.Exec(
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"IDEMPOTENCY_KEY_EXPIRED",
			fmt.Sprintf(`{"key":%q,"route":%q}`, rec.Key, rec.Route), ts,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: idempotency expiry audit: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: commit idempotency reuse: %w", err)
		}
		return rec, false, nil
	}
}

// GetIdempotency returns the stored record for a key.
func (s *Store) GetIdempotency(key string) (IdempotencyRecord, error) {
	var rec IdempotencyRecord
	err := s.db.QueryRow(
		`SELECT key, route, principal, request_hash, response_status,
		        response_body, created_at, expires_at
		   FROM api_idempotency_keys WHERE key = ?`, key,
	).Scan(&rec.Key, &rec.Route, &rec.Principal, &rec.RequestHash,
		&rec.ResponseStatus, &rec.ResponseBody, &rec.CreatedAt, &rec.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return IdempotencyRecord{}, ErrNotFound
	}
	if err != nil {
		return IdempotencyRecord{}, fmt.Errorf("store: get idempotency: %w", err)
	}
	return rec, nil
}
