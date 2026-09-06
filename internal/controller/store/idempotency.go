package store

import (
	"context"
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
// different route, principal, or request hash (409 IDEMPOTENCY_CONFLICT in the
// API layer).
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
//   - matching key + route/principal/hash (unexpired) -> return stored row and replayed=true;
//   - matching key with different route, principal, or hash (unexpired) -> ErrIdempotencyConflict;
//   - expired row -> replace the row and emit an IDEMPOTENCY_KEY_EXPIRED
//     admin event in the same transaction, return replayed=false.
func (s *Store) StoreIdempotency(rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	s.idempotencyMu.Lock()
	defer s.idempotencyMu.Unlock()

	ts := now()
	expires := rec.ExpiresAt
	if expires == 0 {
		expires = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	rec.ExpiresAt = expires

	// The read-check-write runs in a single BEGIN IMMEDIATE transaction so
	// concurrent callers racing the same key serialize on the write lock:
	// exactly one creates/reuses the row and every other caller observes the
	// winner's record (replay or ErrIdempotencyConflict), per
	// docs/error-codes.md §4. A deferred BEGIN would not be safe here: the
	// read would run on a stale snapshot and the later write upgrade would
	// either hit SQLITE_BUSY_SNAPSHOT or fail the UNIQUE constraint,
	// hard-erroring instead of replaying. BEGIN IMMEDIATE is issued on a
	// dedicated connection because database/sql Begin() issues a deferred
	// BEGIN.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: idempotency conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: begin idempotency: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var existing IdempotencyRecord
	err = conn.QueryRowContext(context.Background(),
		`SELECT key, route, principal, request_hash, response_status,
		        response_body, created_at, expires_at
		   FROM api_idempotency_keys WHERE key = ?`, rec.Key,
	).Scan(&existing.Key, &existing.Route, &existing.Principal, &existing.RequestHash,
		&existing.ResponseStatus, &existing.ResponseBody, &existing.CreatedAt, &existing.ExpiresAt)

	var result IdempotencyRecord
	replayed := false
	conflict := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		rec.CreatedAt = ts
		if _, err := conn.ExecContext(context.Background(),
			`INSERT INTO api_idempotency_keys
			    (key, route, principal, request_hash, response_status,
			     response_body, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.Key, rec.Route, rec.Principal, rec.RequestHash,
			rec.ResponseStatus, rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: insert idempotency: %w", err)
		}
		result = rec
	case err != nil:
		return IdempotencyRecord{}, false, fmt.Errorf("store: get idempotency: %w", err)
	case existing.ExpiresAt > ts && existing.Route == rec.Route &&
		existing.Principal == rec.Principal && existing.RequestHash == rec.RequestHash:
		result, replayed = existing, true
	case existing.ExpiresAt > ts:
		conflict = true
	default:
		// Expired: reuse the key for the new request, recording the expiry as
		// a durable admin event in the same transaction.
		rec.CreatedAt = ts
		if _, err := conn.ExecContext(context.Background(),
			`DELETE FROM api_idempotency_keys WHERE key = ?`, rec.Key,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: expire idempotency delete: %w", err)
		}
		if _, err := conn.ExecContext(context.Background(),
			`INSERT INTO api_idempotency_keys
			    (key, route, principal, request_hash, response_status,
			     response_body, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.Key, rec.Route, rec.Principal, rec.RequestHash,
			rec.ResponseStatus, rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: idempotency reuse insert: %w", err)
		}
		if _, err := conn.ExecContext(context.Background(),
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"IDEMPOTENCY_KEY_EXPIRED",
			fmt.Sprintf(`{"key":%q,"route":%q}`, rec.Key, rec.Route), ts,
		); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: idempotency expiry audit: %w", err)
		}
		result = rec
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: commit idempotency: %w", err)
	}
	committed = true
	if conflict {
		return IdempotencyRecord{}, false, ErrIdempotencyConflict
	}
	return result, replayed, nil
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
