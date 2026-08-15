package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// Service errors. Login always returns ErrInvalidCredentials for both
// unknown users and wrong passwords (no user enumeration); session failures
// collapse to ErrInvalidSession.
var (
	ErrInvalidCredentials      = errors.New("auth: invalid credentials")
	ErrInvalidSession          = errors.New("auth: invalid or expired session")
	ErrUserExists              = errors.New("auth: user already exists")
	ErrAdminAlreadyInitialized = errors.New("auth: administrator already initialized")
)

// DefaultSessionTTL is the web-session lifetime.
const DefaultSessionTTL = 24 * time.Hour

// User is the safe, API-facing identity (no hash material).
type User struct {
	ID       string
	Username string
}

// Session is a created web session. The plaintext token is returned exactly
// once to the caller; the service persists only its SHA-256 hash.
type Session struct {
	ID        string
	User      User
	ExpiresAt int64
}

// AuthService orchestrates password verification and session lifecycle over
// the store. It holds no secret material in memory beyond transient locals.
type AuthService struct {
	store *store.Store
	ttl   time.Duration
	dummy EncodedPassword // burns comparable Argon2 time for unknown users
}

// NewService returns an AuthService with the default session TTL.
func NewService(s *store.Store) *AuthService {
	return NewServiceWithTTL(s, DefaultSessionTTL)
}

// NewServiceWithTTL returns an AuthService with a custom session TTL.
func NewServiceWithTTL(s *store.Store, ttl time.Duration) *AuthService {
	dummy, err := HashPassword("auth-dummy-verification")
	if err != nil {
		dummy = EncodedPassword{}
	}
	return &AuthService{store: s, ttl: ttl, dummy: dummy}
}

// EnsureAdmin creates the first administrator with a freshly generated random
// one-time password when none exists, returning the plaintext exactly once.
// A second call for an existing user is a no-op (created=false). The stored
// row contains only the Argon2id hash of the password.
func (a *AuthService) EnsureAdmin(username string) (password string, created bool, err error) {
	if _, err := a.store.GetUserByUsername(username); err == nil {
		return "", false, nil
	} else if !errors.Is(err, store.ErrUserNotFound) {
		return "", false, err
	}

	secret, err := GenerateSecret(32)
	if err != nil {
		return "", false, err
	}
	enc, err := HashPassword(secret)
	if err != nil {
		return "", false, err
	}
	id, err := newID()
	if err != nil {
		return "", false, err
	}
	if err := a.store.CreateFirstUser(store.UserRecord{
		ID: id, Username: username,
		PasswordHash: enc.Hash, PasswordAlgorithm: enc.Algorithm,
	}); err != nil {
		if errors.Is(err, store.ErrAdminExists) {
			return "", false, nil
		}
		return "", false, err
	}
	return secret, true, nil
}

// BootstrapAdmin atomically creates the first administrator with the requested
// operator password. The password is hashed before any durable mutation, and
// CreateFirstUser's immediate transaction makes retries/races safe: a failed
// hash or losing concurrent request cannot leave a half-initialized account.
func (a *AuthService) BootstrapAdmin(username, password string) error {
	enc, err := HashPassword(password)
	if err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	if err := a.store.CreateFirstUser(store.UserRecord{
		ID: id, Username: username,
		PasswordHash: enc.Hash, PasswordAlgorithm: enc.Algorithm,
	}); err != nil {
		if errors.Is(err, store.ErrAdminExists) {
			return ErrAdminAlreadyInitialized
		}
		return err
	}
	return nil
}

// Login verifies credentials and creates a session. On success it returns the
// session plus the one-time plaintext token; the token hash is persisted.
// A successful login with outdated hash parameters silently rehashes the
// password (verify/migration path).
func (a *AuthService) Login(username, password string) (Session, string, error) {
	rec, err := a.store.GetUserByUsername(username)
	if errors.Is(err, store.ErrUserNotFound) {
		// Burn comparable Argon2 time so user existence is not observable.
		_, _, _ = VerifyPassword(a.dummy, password)
		return Session{}, "", ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, "", err
	}

	ok, rehash, err := VerifyPassword(
		EncodedPassword{Algorithm: rec.PasswordAlgorithm, Hash: rec.PasswordHash},
		password,
	)
	if err != nil {
		return Session{}, "", err
	}
	if !ok {
		return Session{}, "", ErrInvalidCredentials
	}
	if rehash {
		enc, err := HashPassword(password)
		if err != nil {
			return Session{}, "", err
		}
		if err := a.store.SetUserPassword(rec.ID, enc.Algorithm, enc.Hash); err != nil {
			return Session{}, "", err
		}
	}

	token, tokenHash, err := NewSessionToken()
	if err != nil {
		return Session{}, "", err
	}
	sessID, err := newID()
	if err != nil {
		return Session{}, "", err
	}
	nowSec := time.Now().Unix()
	rec2 := store.SessionRecord{
		ID: sessID, UserID: rec.ID, SessionHash: tokenHash,
		ExpiresAt: nowSec + int64(a.ttl.Seconds()), CreatedAt: nowSec,
	}
	if err := a.store.CreateSession(rec2); err != nil {
		return Session{}, "", err
	}
	return Session{
		ID:        rec2.ID,
		User:      User{ID: rec.ID, Username: rec.Username},
		ExpiresAt: rec2.ExpiresAt,
	}, token, nil
}

// Me resolves a session token to its user. Revoked and expired sessions fail.
func (a *AuthService) Me(token string) (User, error) {
	rec, err := a.sessionFor(token)
	if err != nil {
		return User{}, err
	}
	u, err := a.store.GetUserByID(rec.UserID)
	if errors.Is(err, store.ErrUserNotFound) {
		return User{}, ErrInvalidSession
	}
	if err != nil {
		return User{}, err
	}
	return User{ID: u.ID, Username: u.Username}, nil
}

// Logout revokes a session token. Revoking an unknown session is idempotent.
func (a *AuthService) Logout(token string) error {
	if token == "" {
		return ErrInvalidSession
	}
	sum := sha256.Sum256([]byte(token))
	err := a.store.RevokeSession(hex.EncodeToString(sum[:]))
	if errors.Is(err, store.ErrNotFound) {
		return nil // already gone
	}
	return err
}

// sessionFor validates a token and returns its unexpired, unrevoked session.
func (a *AuthService) sessionFor(token string) (store.SessionRecord, error) {
	if token == "" {
		return store.SessionRecord{}, ErrInvalidSession
	}
	sum := sha256.Sum256([]byte(token))
	rec, err := a.store.GetSessionByHash(hex.EncodeToString(sum[:]))
	if errors.Is(err, store.ErrNotFound) {
		return store.SessionRecord{}, ErrInvalidSession
	}
	if err != nil {
		return store.SessionRecord{}, err
	}
	if rec.RevokedAt != 0 {
		return store.SessionRecord{}, ErrInvalidSession
	}
	if rec.ExpiresAt <= time.Now().Unix() {
		return store.SessionRecord{}, ErrInvalidSession
	}
	return rec, nil
}
