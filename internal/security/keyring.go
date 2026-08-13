// Controller signing keyring (Story 1/2).
//
// The Controller signs enrollment transcripts and session handshakes with a
// single Ed25519 signing key persisted secret-safe (0600 atomic file on Unix,
// DPAPI on Windows). The key ID is derived deterministically from the public
// key so it is stable across reloads and rotation generations can be tracked
// (generation downgrade fails closed).
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gxbrave/AntiNAT/internal/security/framecrypto"
)

// KeyringFile is the Controller signing key filename.
const KeyringFile = "controller-signing.key"

// maxSupportedGeneration is the highest keyring generation this build
// understands. A file carrying a higher generation was written by a newer
// AntiNAT build and load fails closed (mirrors the bbolt schema gate).
// P14 rotation raises this bound.
const maxSupportedGeneration uint64 = 1

// keyringMagic identifies the keyring file format.
var keyringMagic = [4]byte{'A', 'N', 'K', 'C'}

// Keyring is the Controller signing key with its generation.
type Keyring struct {
	priv       ed25519.PrivateKey
	generation uint64
}

// LoadOrCreateKeyring loads the Controller signing key from dir, generating
// and durably persisting a fresh key when none exists. A future generation
// (downgrade protection) fails closed.
func LoadOrCreateKeyring(dir string, generation uint64) (*Keyring, error) {
	if generation == 0 {
		return nil, errors.New("security: keyring generation must be non-zero")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("security: create keyring dir: %w", err)
	}
	path := filepath.Join(dir, KeyringFile)
	raw, err := loadKeyFile(path)
	if err == nil {
		return parseKeyring(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("security: generate keyring: %w", err)
	}
	kr := &Keyring{priv: priv, generation: generation}
	if err := kr.saveAtomic(path); err != nil {
		if raw2, err2 := loadKeyFile(path); err2 == nil {
			return parseKeyring(raw2)
		}
		return nil, err
	}
	raw, err = loadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("security: reload keyring after write: %w", err)
	}
	return parseKeyring(raw)
}

func parseKeyring(raw []byte) (*Keyring, error) {
	if len(raw) != 4+8+ed25519.PrivateKeySize {
		return nil, errors.New("security: keyring file has invalid length")
	}
	if string(raw[:4]) != string(keyringMagic[:]) {
		return nil, errors.New("security: keyring file has invalid magic")
	}
	generation := binary.BigEndian.Uint64(raw[4:12])
	if generation == 0 {
		return nil, errors.New("security: keyring file has zero generation")
	}
	if generation > maxSupportedGeneration {
		return nil, fmt.Errorf("security: keyring generation %d is newer than this build supports (%d)", generation, maxSupportedGeneration)
	}
	priv := ed25519.PrivateKey(append([]byte(nil), raw[12:]...))
	return &Keyring{priv: priv, generation: generation}, nil
}

func (k *Keyring) saveAtomic(path string) error {
	blob := make([]byte, 0, 4+8+ed25519.PrivateKeySize)
	blob = append(blob, keyringMagic[:]...)
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], k.generation)
	blob = append(blob, g[:]...)
	blob = append(blob, k.priv...)
	return writeKeyFileAtomic(path, blob)
}

// PublicKey returns the Controller signing public key.
func (k *Keyring) PublicKey() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// KeyID returns the deterministic key ID (hex of the first 8 bytes of the
// public key hash) — stable across reloads and used in enrollment results,
// session welcomes, and envelope headers.
func (k *Keyring) KeyID() string {
	sum := sha256.Sum256(k.PublicKey())
	return hex.EncodeToString(sum[:8])
}

// Generation returns the key generation (anti-downgrade).
func (k *Keyring) Generation() uint64 { return k.generation }

// Sign signs msg with the Controller signing key.
func (k *Keyring) Sign(msg []byte) ([]byte, error) {
	return framecrypto.Sign(k.priv, msg)
}

// VerifyKeyringSignature verifies msg/sig against the given public key.
func VerifyKeyringSignature(pub ed25519.PublicKey, msg, sig []byte) bool {
	return framecrypto.Verify(pub, msg, sig)
}
