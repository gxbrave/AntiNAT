// Package auth implements the Controller authentication service layer:
// Argon2id password hashing with versioned parameters (verify + silent
// rehash migration), random secret generation, and session token hashing.
// It deliberately has no HTTP handlers (P15 owns the API layer) and never
// logs or persists plaintext passwords or session tokens.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordAlgorithmArgon2id is the current password hashing scheme recorded in
// users.password_algorithm.
const PasswordAlgorithmArgon2id = "argon2id-v19"

// Current Argon2id parameters (OWASP-recommended baseline).
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// EncodedPassword is a password hash plus its algorithm name. Hash is the PHC
// string: $argon2id$v=19$m=...,t=...,p=...$salt$hash
type EncodedPassword struct {
	Algorithm string
	Hash      string
}

// HashPassword hashes a password with the current recommended parameters.
func HashPassword(password string) (EncodedPassword, error) {
	return HashPasswordWithParams(password, argon2Memory, argon2Time, argon2Threads)
}

// HashPasswordWithParams hashes a password with explicit Argon2id parameters;
// used by tests to produce an outdated hash that must still verify while
// signalling needsRehash.
func HashPasswordWithParams(password string, memory, time, threads uint32) (EncodedPassword, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return EncodedPassword{}, fmt.Errorf("auth: hash salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), argon2KeyLen)
	enc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
	return EncodedPassword{Algorithm: PasswordAlgorithmArgon2id, Hash: enc}, nil
}

// VerifyPassword checks a password against an encoded hash. It returns
// ok=false for a wrong password and needsRehash=true when the stored hash
// uses parameters weaker than the current recommendation (the caller should
// silently rehash on the next successful login).
func VerifyPassword(enc EncodedPassword, password string) (ok, needsRehash bool, err error) {
	parts := strings.Split(enc.Hash, "$")
	// $ argon2id v=19 params salt hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, errors.New("auth: unsupported password hash format")
	}
	params := strings.Split(parts[3], ",")
	memory, timeCost, threads := uint32(0), uint32(0), uint32(0)
	for _, p := range params {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return false, false, errors.New("auth: malformed hash parameters")
		}
		v, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false, false, fmt.Errorf("auth: malformed hash parameter %q", p)
		}
		switch kv[0] {
		case "m":
			memory = uint32(v)
		case "t":
			timeCost = uint32(v)
		case "p":
			threads = uint32(v)
		default:
			return false, false, fmt.Errorf("auth: unknown hash parameter %q", kv[0])
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, errors.New("auth: malformed hash salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return false, false, errors.New("auth: malformed hash value")
	}

	actual := argon2.IDKey([]byte(password), salt, timeCost, memory, uint8(threads), uint32(len(expected)))
	ok = subtle.ConstantTimeCompare(actual, expected) == 1
	needsRehash = memory != argon2Memory || timeCost != argon2Time || threads != argon2Threads
	return ok, needsRehash, nil
}

// GenerateSecret returns a URL-safe random secret of byteLen random bytes
// (base64url, no padding). Used for the one-time bootstrap admin password.
func GenerateSecret(byteLen int) (string, error) {
	if byteLen < 1 {
		return "", errors.New("auth: secret length must be >= 1")
	}
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewSessionToken returns a random session token and its SHA-256 hex hash.
// Only the hash is ever persisted.
func NewSessionToken() (token, tokenHash string, err error) {
	token, err = GenerateSecret(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// newID returns a random hex identifier.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
