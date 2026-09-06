package hook

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// SecretKeystore encrypts hook-secret values at rest with AES-256-GCM. The
// plaintext value is set once at create (ciphertext stored in hook_secrets) and
// is never returned by the API; the broker decrypts it in-process for the ONE
// normalized final request it signs (v0.8 §8.2/§8.3). The key file is 0600 and
// is created on first use.
type SecretKeystore struct {
	mu    sync.RWMutex
	path  string
	keyID string
	key   []byte // 32-byte symmetric key
	aead  cipher.AEAD
}

// ErrSecretKeyMismatch is returned when ciphertext references an unknown key id
// (future rotation without rewrap) — fail closed, never guess.
var ErrSecretKeyMismatch = errors.New("hook: secret ciphertext key id is unknown")

var secretKeyMagic = [4]byte{'A', 'N', 'H', 'K'}

// LoadOrCreateSecretKey loads the AES-256-GCM key file at path, or creates it
// atomically with a fresh random key on first use.
func LoadOrCreateSecretKey(path string) (*SecretKeystore, error) {
	if path == "" {
		return nil, errors.New("hook: secret key path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("hook: secret key dir: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		// Enforce the strict key file permissions on load (fail closed): a key
		// file that is group/other-readable could have been tampered with or
		// mis-created, and a corrupt partial write must never silently disable
		// later starts. Best-effort on platforms where chmod is meaningless
		// (e.g. Windows file permission semantics differ).
		if err := checkSecretKeyFilePerms(path); err != nil {
			return nil, err
		}
		keyID, key, err := parseSecretKeyFile(raw)
		if err != nil {
			return nil, err
		}
		return newSecretKeystore(path, keyID, key)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("hook: read secret key: %w", err)
	}
	// Create the key file atomically (temp file in the same dir + fsync +
	// rename) with strict 0600 perms and a random 32-byte AES key plus a random
	// key id. A crash mid-write can never leave a truncated file at the final
	// path that would permanently fail later starts.
	keyID, err := randomKeyID()
	if err != nil {
		return nil, fmt.Errorf("hook: key id: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("hook: key material: %w", err)
	}
	file := make([]byte, 0, len(secretKeyMagic)+1+1+len(keyID)+len(key))
	file = append(file, secretKeyMagic[:]...)
	file = append(file, 1) // format version
	file = append(file, byte(len(keyID)))
	file = append(file, keyID...)
	file = append(file, key...)
	if err := writeSecretKeyFileAtomic(path, file, 0o600); err != nil {
		return nil, fmt.Errorf("hook: write secret key: %w", err)
	}
	return newSecretKeystore(path, keyID, key)
}

// writeSecretKeyFileAtomic writes raw to path atomically: a temp file in the
// same directory is created with strict permissions, written, fsynced, and then
// renamed over the target so a reader/restart never sees a partially-written
// key file. The containing directory is fsynced best-effort so the rename is
// durable across a crash.
func writeSecretKeyFileAtomic(path string, raw []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".antinat-key-*")
	if err != nil {
		return fmt.Errorf("hook: create temp key: %w", err)
	}
	tmpName := tmp.Name()
	removed := false
	defer func() {
		tmp.Close()
		if !removed {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	removed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// checkSecretKeyFilePerms verifies the secret key file is a regular 0600 file
// (group/other bits clear). Fails closed on any deviation so a mis-permissioned
// or corrupt file is never silently accepted. Best-effort on Windows where
// POSIX permission semantics are not meaningful.
func checkSecretKeyFilePerms(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("hook: stat secret key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("hook: secret key path %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("hook: secret key file %s has permissions %04o, want 0600 (fail closed)", path, perm)
	}
	return nil
}

func newSecretKeystore(path, keyID string, key []byte) (*SecretKeystore, error) {
	if len(key) != 32 {
		return nil, errors.New("hook: secret key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("hook: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("hook: gcm: %w", err)
	}
	return &SecretKeystore{path: path, keyID: keyID, key: key, aead: aead}, nil
}

func parseSecretKeyFile(raw []byte) (string, []byte, error) {
	if len(raw) < len(secretKeyMagic)+2+8+32 {
		return "", nil, errors.New("hook: secret key file too short")
	}
	if string(raw[:4]) != string(secretKeyMagic[:]) {
		return "", nil, errors.New("hook: secret key file has an invalid magic")
	}
	if raw[4] != 1 {
		return "", nil, errors.New("hook: unsupported secret key file version")
	}
	idLen := int(raw[5])
	if len(raw) != len(secretKeyMagic)+2+idLen+32 || idLen <= 0 {
		return "", nil, errors.New("hook: secret key file has an invalid key id")
	}
	keyID := string(raw[6 : 6+idLen])
	key := raw[6+idLen:]
	return keyID, key, nil
}

func randomKeyID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// KeyID returns the active key id (test/operational hook; the value is also
// stored with every ciphertext so rotation can rewrap later).
func (k *SecretKeystore) KeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keyID
}

// SecretNonceSize is the AES-GCM nonce length (12 bytes); the keystore stores
// it as the ciphertext blob prefix.
const SecretNonceSize = 12

// Encrypt seals one secret value as one blob: nonce || ciphertext. The nonce is
// random per call (never reused) and stored adjacent so a single hook_secrets
// BLOB column keeps the encryption self-contained.
func (k *SecretKeystore) Encrypt(plaintext []byte) ([]byte, string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("hook: nonce: %w", err)
	}
	sealed := k.aead.Seal(nil, nonce, plaintext, nil)
	blob := make([]byte, 0, len(nonce)+len(sealed))
	blob = append(blob, nonce...)
	blob = append(blob, sealed...)
	return blob, k.keyID, nil
}

// Decrypt opens one secret value blob (nonce || ciphertext). It fails closed
// on an unknown key id or an undecryptable blob.
func (k *SecretKeystore) Decrypt(keyID string, blob []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.keyID != keyID {
		return nil, fmt.Errorf("%w: have %s, want %s", ErrSecretKeyMismatch, keyID, k.keyID)
	}
	if len(blob) < SecretNonceSize {
		return nil, errors.New("hook: secret ciphertext is truncated")
	}
	nonce := blob[:SecretNonceSize]
	sealed := blob[SecretNonceSize:]
	plain, err := k.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, errors.New("hook: secret decryption failed")
	}
	return plain, nil
}
