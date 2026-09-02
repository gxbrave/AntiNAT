package hook_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

// RED P16 Story 3 (a): the secret keystore encrypts values at rest with a
// fresh random nonce and decrypts them back; the ciphertext blob is self
// contained (nonce prefix) and the key file is created on first use.
func TestSecretKeystoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-secret.key")
	ks, err := hook.LoadOrCreateSecretKey(path)
	if err != nil {
		t.Fatal(err)
	}
	blob, keyID, err := ks.Encrypt([]byte("AccessKeySecret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) <= hook.SecretNonceSize {
		t.Fatalf("ciphertext blob too small: %d", len(blob))
	}
	got, err := ks.Decrypt(keyID, blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "AccessKeySecret-value" {
		t.Fatalf("round trip = %q", got)
	}
	// A second encryption produces a different nonce (never reused).
	blob2, _, err := ks.Encrypt([]byte("same-value"))
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) == string(blob2) {
		t.Fatal("nonce/ciphertext reused across encryptions")
	}
}

// RED P16 Story 3 (b): reopening the key file yields the same key (the value
// can be decrypted after a restart).
func TestSecretKeystorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-secret.key")
	ks, _ := hook.LoadOrCreateSecretKey(path)
	blob, keyID, _ := ks.Encrypt([]byte("persisted-value"))
	reopened, err := hook.LoadOrCreateSecretKey(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Decrypt(keyID, blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "persisted-value" {
		t.Fatalf("reopen decrypt = %q", got)
	}
}

// RED P16 Story 3 (c): decryption fails closed for a truncated blob and for a
// blob under an unknown (rotated) key id — never a silent guess.
func TestSecretKeystoreFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-secret.key")
	ks, _ := hook.LoadOrCreateSecretKey(path)
	if _, err := ks.Decrypt(ks.KeyID(), []byte("short")); err == nil {
		t.Fatal("truncated blob decrypted")
	}
	if _, err := ks.Decrypt("unknown-key-id", make([]byte, hook.SecretNonceSize+16)); err == nil ||
		!errors.Is(err, hook.ErrSecretKeyMismatch) {
		t.Fatalf("unknown key id error = %v, want ErrSecretKeyMismatch", err)
	}
	tampered := make([]byte, hook.SecretNonceSize+16)
	if _, err := ks.Decrypt(ks.KeyID(), tampered); err == nil {
		t.Fatal("tampered ciphertext authenticated")
	}
}

// RED P16 Story 3 (d): the key file load rejects a wrong magic / short file
// (fails closed rather than misinterpreting).
func TestSecretKeystoreRejectsBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook-secret.key")
	if err := os.WriteFile(path, []byte("garbage-not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hook.LoadOrCreateSecretKey(path); err == nil {
		t.Fatal("garbage key file accepted")
	}
}
