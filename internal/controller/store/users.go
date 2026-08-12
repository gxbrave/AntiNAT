package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// ErrUserNotFound is returned when no user matches a lookup.
var ErrUserNotFound = errors.New("store: user not found")

// UserRecord is a persistent administrator row. PasswordHash is always the
// encoded password hash (never the plaintext); PasswordAlgorithm records the
// hashing scheme used so a future algorithm can be verified and migrated.
type UserRecord struct {
	ID                string
	Username          string
	PasswordHash      string
	PasswordAlgorithm string
	Revision          uint64
	CreatedAt         int64
	UpdatedAt         int64
}

// CreateUser inserts an administrator row. Username is unique.
func (s *Store) CreateUser(u UserRecord) error {
	ts := now()
	_, err := s.db.Exec(
		`INSERT INTO users (id, username, password_hash, password_algorithm,
		                    revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.PasswordAlgorithm,
		u.Revision, ts, ts,
	)
	if err != nil {
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

// GetUserByUsername returns a user row by username.
func (s *Store) GetUserByUsername(username string) (UserRecord, error) {
	return s.scanUser("username = ?", username)
}

// GetUserByID returns a user row by id.
func (s *Store) GetUserByID(id string) (UserRecord, error) {
	return s.scanUser("id = ?", id)
}

func (s *Store) scanUser(where string, arg any) (UserRecord, error) {
	var u UserRecord
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, password_algorithm,
		        revision, created_at, updated_at
		   FROM users WHERE `+where, arg,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.PasswordAlgorithm,
		&u.Revision, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return UserRecord{}, ErrUserNotFound
	}
	if err != nil {
		return UserRecord{}, fmt.Errorf("store: get user: %w", err)
	}
	return u, nil
}

// SetUserPassword rotates the stored password hash/algorithm and bumps the
// user revision. The plaintext password never reaches this layer.
func (s *Store) SetUserPassword(id, algorithm, hash string) error {
	res, err := s.db.Exec(
		`UPDATE users
		    SET password_hash = ?, password_algorithm = ?,
		        revision = revision + 1, updated_at = ?
		  WHERE id = ?`,
		hash, algorithm, now(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set user password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set user password rows: %w", err)
	}
	if n != 1 {
		return ErrUserNotFound
	}
	return nil
}

// SessionRecord is a web admin session row. SessionHash is the SHA-256 of the
// random session token (the plaintext token is never stored).
type SessionRecord struct {
	ID          string
	UserID      string
	SessionHash string
	ExpiresAt   int64
	RevokedAt   int64
	CreatedAt   int64
	IP          string
	UserAgent   string
}

// CreateSession inserts a session row.
func (s *Store) CreateSession(rec SessionRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO web_sessions
		    (id, user_id, session_hash, expires_at, revoked_at, created_at, ip, user_agent)
		 VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`,
		rec.ID, rec.UserID, rec.SessionHash, rec.ExpiresAt, rec.CreatedAt, rec.IP, rec.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSessionByHash returns a session row by its token hash.
func (s *Store) GetSessionByHash(hash string) (SessionRecord, error) {
	var rec SessionRecord
	var revokedAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT id, user_id, session_hash, expires_at, revoked_at, created_at, ip, user_agent
		   FROM web_sessions WHERE session_hash = ?`, hash,
	).Scan(&rec.ID, &rec.UserID, &rec.SessionHash, &rec.ExpiresAt, &revokedAt,
		&rec.CreatedAt, &rec.IP, &rec.UserAgent)
	rec.RevokedAt = revokedAt.Int64
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRecord{}, ErrNotFound
	}
	if err != nil {
		return SessionRecord{}, fmt.Errorf("store: get session: %w", err)
	}
	return rec, nil
}

// RevokeSession marks a session revoked at the current time.
func (s *Store) RevokeSession(hash string) error {
	res, err := s.db.Exec(
		`UPDATE web_sessions SET revoked_at = ? WHERE session_hash = ?`,
		now(), hash,
	)
	if err != nil {
		return fmt.Errorf("store: revoke session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: revoke session rows: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
