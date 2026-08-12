package auth_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func openAuth(t *testing.T) (*auth.AuthService, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return auth.NewService(s), s
}

// RED 4a: an Argon2id hash verifies its own password and rejects others.
func TestHashPasswordRoundTrip(t *testing.T) {
	enc, err := auth.HashPassword("hunter2-secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if enc.Algorithm != auth.PasswordAlgorithmArgon2id {
		t.Fatalf("algorithm = %q, want %q", enc.Algorithm, auth.PasswordAlgorithmArgon2id)
	}
	if strings.Contains(enc.Hash, "hunter2-secret") {
		t.Fatal("encoded hash contains the plaintext password")
	}

	ok, rehash, err := auth.VerifyPassword(enc, "hunter2-secret")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok || rehash {
		t.Fatalf("VerifyPassword = (ok=%v rehash=%v), want (true, false)", ok, rehash)
	}

	if ok, _, _ := auth.VerifyPassword(enc, "wrong"); ok {
		t.Fatal("wrong password verified")
	}
}

// RED 4b: a hash produced with outdated (weaker) Argon2id parameters still
// verifies, but signals needsRehash so the service can migrate it.
func TestVerifyMigratesOutdatedParams(t *testing.T) {
	// Lower memory cost than the current recommendation.
	old, err := auth.HashPasswordWithParams("hunter2-secret", 8192, 3, 4)
	if err != nil {
		t.Fatalf("HashPasswordWithParams: %v", err)
	}

	ok, rehash, err := auth.VerifyPassword(old, "hunter2-secret")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("outdated-params hash did not verify")
	}
	if !rehash {
		t.Fatal("outdated-params hash did not signal needsRehash")
	}
}

// RED Q1 (repair cycle 1): VerifyPassword must return an error, never panic,
// when the stored hash carries malformed Argon2id parameters (t=0, p=0,
// p=256 wrapping to 0 via uint8, or memory above the safety cap). A
// corrupted/tampered database must fail closed on the next Login instead of
// crashing the whole controller (Story-6 fail-closed design).
func TestVerifyPasswordRejectsMalformedParams(t *testing.T) {
	phc := func(t, m, p uint32, keyLen int) string {
		salt := make([]byte, 16)
		key := make([]byte, keyLen)
		return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
			m, t, p,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(key))
	}
	cases := []struct {
		name string
		hash string
	}{
		{"t=0 rounds", phc(0, 65536, 4, 32)},
		{"p=0 threads", phc(3, 65536, 0, 32)},
		{"p=256 wraps to 0 via uint8", phc(3, 65536, 256, 32)},
		{"m above 1 GiB cap", phc(3, 1<<21, 4, 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := auth.VerifyPassword(
				auth.EncodedPassword{Algorithm: auth.PasswordAlgorithmArgon2id, Hash: tc.hash},
				"whatever",
			)
			if err == nil {
				t.Fatalf("VerifyPassword accepted malformed hash %q", tc.hash)
			}
		})
	}
}

// RED 4c: random secret generation produces distinct, sufficiently long
// secrets (bootstrap admin password path).
func TestGenerateSecretIsRandomAndLong(t *testing.T) {
	a, err := auth.GenerateSecret(32)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := auth.GenerateSecret(32)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(a) < 32 || len(b) < 32 {
		t.Fatalf("secrets too short: %d / %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("two secrets are identical")
	}
	if strings.Contains(a, "=") || strings.Contains(a, "+") || strings.Contains(a, "/") {
		t.Fatalf("secret contains non-URL-safe characters: %q", a)
	}
}

// RED 4d: session tokens are random; only their SHA-256 hash is persisted and
// the plaintext token is never written to the database.
func TestNewSessionTokenHashedAndRandom(t *testing.T) {
	tok1, h1, err := auth.NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	tok2, h2, err := auth.NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("two session tokens are identical")
	}
	if h1 == tok1 || h2 == tok2 {
		t.Fatal("session hash equals plaintext token")
	}
	if len(h1) != 64 {
		t.Fatalf("session hash length = %d, want 64 (SHA-256 hex)", len(h1))
	}
}

// RED 4e: EnsureAdmin creates the first admin with a random one-time password
// and stores only its hash.
func TestEnsureAdminGeneratesOneTimePassword(t *testing.T) {
	svc, s := openAuth(t)

	password, created, err := svc.EnsureAdmin("admin")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	if !created || password == "" {
		t.Fatalf("EnsureAdmin = (pw=%q created=%v), want non-empty and created", password, created)
	}

	// A second call must not reset the password.
	_, created2, err := svc.EnsureAdmin("admin")
	if err != nil {
		t.Fatalf("EnsureAdmin second: %v", err)
	}
	if created2 {
		t.Fatal("EnsureAdmin re-created an existing admin")
	}

	// The stored hash is not the one-time password.
	rec, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if rec.PasswordHash == password || strings.Contains(rec.PasswordHash, password) {
		t.Fatal("plaintext admin password persisted")
	}

	// The one-time password actually logs in.
	if _, _, err := svc.Login("admin", password); err != nil {
		t.Fatalf("Login with one-time password: %v", err)
	}
}

// RED 4f: Login/Logout/Me flow; Me fails after logout and on expiry.
func TestLoginLogoutMe(t *testing.T) {
	svc, _ := openAuth(t)
	password, _, err := svc.EnsureAdmin("admin")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}

	sess, token, err := svc.Login("admin", password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.User.Username != "admin" || token == "" {
		t.Fatalf("Login session = %+v token=%q", sess, token)
	}

	me, err := svc.Me(token)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if me.Username != "admin" {
		t.Fatalf("Me = %+v", me)
	}

	if err := svc.Logout(token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Me(token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("Me after logout = %v, want ErrInvalidSession", err)
	}
}

// RED 4g: a wrong password is rejected without revealing whether the user
// exists (single generic error).
func TestLoginWrongPassword(t *testing.T) {
	svc, _ := openAuth(t)
	password, _, err := svc.EnsureAdmin("admin")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	if _, _, err := svc.Login("admin", password+"x"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login("no-such-user", "whatever"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login unknown user = %v, want ErrInvalidCredentials (no user enumeration)", err)
	}
}

// RED 4h: sessions honour their expiry.
func TestSessionExpiry(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	svc := auth.NewServiceWithTTL(s, time.Second)

	password, _, err := svc.EnsureAdmin("admin")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	_, token, err := svc.Login("admin", password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := svc.Me(token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("Me after expiry = %v, want ErrInvalidSession", err)
	}
}

// RED 4i: logging in with an outdated-parameter hash silently rehashes it, so
// a subsequent verify no longer signals needsRehash.
func TestLoginMigratesHash(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	old, err := auth.HashPasswordWithParams("pw-secret", 8192, 3, 4)
	if err != nil {
		t.Fatalf("HashPasswordWithParams: %v", err)
	}
	if err := s.CreateUser(store.UserRecord{
		ID: "u-1", Username: "admin",
		PasswordHash: old.Hash, PasswordAlgorithm: old.Algorithm,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	svc := auth.NewService(s)
	if _, _, err := svc.Login("admin", "pw-secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	rec, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	ok, rehash, err := auth.VerifyPassword(
		auth.EncodedPassword{Algorithm: rec.PasswordAlgorithm, Hash: rec.PasswordHash},
		"pw-secret",
	)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("migrated hash does not verify")
	}
	if rehash {
		t.Fatal("migrated hash still signals needsRehash")
	}
}
