package store_test

import (
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func openUsers(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// RED 4a: a user row persists exactly the encoded hash (never the plaintext
// password) and can be looked up by username.
func TestCreateUserStoresOnlyHash(t *testing.T) {
	s := openUsers(t)

	plaintext := "correct horse battery staple"
	if err := s.CreateUser(store.UserRecord{
		ID: "u-1", Username: "admin",
		PasswordHash: "ARGON2ID-HASH-BYTES", PasswordAlgorithm: "argon2id-v19",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.PasswordHash == plaintext {
		t.Fatal("plaintext password stored in users.password_hash")
	}
	if got.PasswordHash != "ARGON2ID-HASH-BYTES" || got.PasswordAlgorithm != "argon2id-v19" {
		t.Fatalf("user row = %+v", got)
	}
}

// RED 4b: a missing user surfaces ErrUserNotFound.
func TestGetUserByUsernameNotFound(t *testing.T) {
	s := openUsers(t)
	if _, err := s.GetUserByUsername("nobody"); err != store.ErrUserNotFound {
		t.Fatalf("GetUserByUsername(nobody) = %v, want ErrUserNotFound", err)
	}
}

// RED 4c: password rotation replaces the hash and bumps the revision.
func TestSetUserPasswordRotatesHash(t *testing.T) {
	s := openUsers(t)
	if err := s.CreateUser(store.UserRecord{
		ID: "u-1", Username: "admin",
		PasswordHash: "OLD-HASH", PasswordAlgorithm: "argon2id-v19",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := s.SetUserPassword("u-1", "argon2id-v19", "NEW-HASH"); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	got, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.PasswordHash != "NEW-HASH" {
		t.Fatalf("password hash = %q, want NEW-HASH", got.PasswordHash)
	}
	if got.Revision != 1 {
		t.Fatalf("user revision = %d, want 1", got.Revision)
	}
}

// RED 4d: a session row persists the token hash (never the plaintext token)
// with an explicit expiry; lookup by hash works.
func TestCreateSessionStoresOnlyHash(t *testing.T) {
	s := openUsers(t)

	if err := s.CreateUser(store.UserRecord{
		ID: "u-1", Username: "admin",
		PasswordHash: "HASH", PasswordAlgorithm: "argon2id-v19",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext := "session-token-plaintext"
	if err := s.CreateSession(store.SessionRecord{
		ID: "sess-1", UserID: "u-1",
		SessionHash: "SHA256-OF-TOKEN", ExpiresAt: 9999999999, CreatedAt: 1,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := s.GetSessionByHash("SHA256-OF-TOKEN")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if got.SessionHash == plaintext {
		t.Fatal("plaintext session token stored in web_sessions.session_hash")
	}
	if got.SessionHash != "SHA256-OF-TOKEN" || got.UserID != "u-1" {
		t.Fatalf("session row = %+v", got)
	}
}

// RED 4e: revocation sets revoked_at so a revoked session is distinguishable
// from an expired one.
func TestRevokeSession(t *testing.T) {
	s := openUsers(t)
	if err := s.CreateUser(store.UserRecord{
		ID: "u-1", Username: "admin",
		PasswordHash: "HASH", PasswordAlgorithm: "argon2id-v19",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.CreateSession(store.SessionRecord{
		ID: "sess-1", UserID: "u-1",
		SessionHash: "HASH", ExpiresAt: 9999999999, CreatedAt: 1,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.RevokeSession("HASH"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	got, err := s.GetSessionByHash("HASH")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if got.RevokedAt == 0 {
		t.Fatal("revoked session has revoked_at == 0")
	}
}
