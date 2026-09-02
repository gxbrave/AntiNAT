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
		keyID, key, err := parseSecretKeyFile(raw)
		if err != nil {
			return nil, err
		}
		return newSecretKeystore(path, keyID, key)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("hook: read secret key: %w", err)
	}
	// Create the key file with strict permissions (0600) and a random 32-byte
	// AES key plus a random key id.
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
	if err := os.WriteFile(path, file, 0o600); err != nil {
		return nil, fmt.Errorf("hook: write secret key: %w", err)
	}
	return newSecretKeystore(path, keyID, key)
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
