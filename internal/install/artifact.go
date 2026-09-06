package install

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	ArtifactManifestSchema = "1"
	maxManifestBytes       = 1 << 20
	maxArtifactBytes       = 512 << 20
)

// ArtifactManifest is the signed release manifest. The detached signature is
// intentionally not a field: the signature covers the exact manifest bytes
// fetched from the release location and is supplied separately.
type ArtifactManifest struct {
	SchemaVersion      string            `json:"schema_version"`
	Release            string            `json:"release,omitempty"`
	Artifacts          map[string]string `json:"artifacts"`
	TrustRoot          string            `json:"trust_root"`
	SignatureAlgorithm string            `json:"signature_algorithm,omitempty"`
}

// ParseArtifactManifest validates the untrusted JSON before it is used for any
// file access. Unknown fields are rejected so a later parser cannot silently
// assign a different meaning to signed bytes.
func ParseArtifactManifest(raw []byte) (ArtifactManifest, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return ArtifactManifest{}, artifactError(errors.New("manifest is empty or exceeds size limit"))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var manifest ArtifactManifest
	if err := dec.Decode(&manifest); err != nil {
		return ArtifactManifest{}, artifactError(fmt.Errorf("decode manifest: %w", err))
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return ArtifactManifest{}, artifactError(errors.New("manifest has trailing JSON values"))
		}
		return ArtifactManifest{}, artifactError(fmt.Errorf("manifest has trailing data: %w", err))
	}
	if err := validateArtifactManifest(manifest); err != nil {
		return ArtifactManifest{}, artifactError(err)
	}
	return manifest, nil
}

func validateArtifactManifest(manifest ArtifactManifest) error {
	if manifest.SchemaVersion != ArtifactManifestSchema {
		return fmt.Errorf("manifest schema_version must be %q", ArtifactManifestSchema)
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("manifest contains no artifacts")
	}
	if strings.TrimSpace(manifest.TrustRoot) == "" {
		return errors.New("manifest trust_root is required")
	}
	if manifest.SignatureAlgorithm != "" && manifest.SignatureAlgorithm != "ed25519" {
		return fmt.Errorf("unsupported manifest signature algorithm %q", manifest.SignatureAlgorithm)
	}
	for name, digest := range manifest.Artifacts {
		if err := validateArtifactName(name); err != nil {
			return err
		}
		if len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
			return fmt.Errorf("artifact %q digest must be lowercase sha256 hex", name)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("artifact %q digest is not hex: %w", name, err)
		}
	}
	return nil
}

func validateArtifactName(name string) error {
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == "." || name == ".." {
		return fmt.Errorf("artifact name %q is not a safe relative path", name)
	}
	if strings.ContainsAny(name, "\\:\x00") {
		return fmt.Errorf("artifact name %q contains an unsafe path character", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("artifact name %q contains an unsafe path component", name)
		}
	}
	return nil
}

// VerifySignedManifest checks the detached Ed25519 signature against the
// pinned key selected by manifest.TrustRoot. The caller must pass the exact
// bytes downloaded; re-marshalling JSON before this check is not permitted.
func VerifySignedManifest(rawManifest, detachedSignature []byte, roots map[string]ed25519.PublicKey) (ArtifactManifest, error) {
	manifest, err := ParseArtifactManifest(rawManifest)
	if err != nil {
		return ArtifactManifest{}, err
	}
	root, ok := roots[manifest.TrustRoot]
	if !ok || len(root) != ed25519.PublicKeySize {
		return ArtifactManifest{}, artifactError(fmt.Errorf("pinned trust root %q is unavailable", manifest.TrustRoot))
	}
	signature, err := decodeDetachedSignature(detachedSignature)
	if err != nil {
		return ArtifactManifest{}, artifactError(err)
	}
	if !ed25519.Verify(root, rawManifest, signature) {
		return ArtifactManifest{}, artifactError(errors.New("detached manifest signature verification failed"))
	}
	return manifest, nil
}

// VerifyArtifactSet checks every manifest digest before an artifact is
// executable or installed. Symlinks, directories and path escapes are
// rejected. It is intentionally all-or-nothing from the caller's perspective:
// no destination mutation occurs in this function.
func VerifyArtifactSet(root string, manifest ArtifactManifest) error {
	if err := validateArtifactManifest(manifest); err != nil {
		return artifactError(err)
	}
	if root == "" {
		return artifactError(errors.New("artifact root is required"))
	}
	for name, expected := range manifest.Artifacts {
		path, err := secureJoin(root, name)
		if err != nil {
			return artifactError(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return artifactError(fmt.Errorf("stat artifact %q: %w", name, err))
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return artifactError(fmt.Errorf("artifact %q is not a regular non-symlink file", name))
		}
		if info.Size() > maxArtifactBytes {
			return artifactError(fmt.Errorf("artifact %q exceeds size limit", name))
		}
		file, err := os.Open(path)
		if err != nil {
			return artifactError(fmt.Errorf("open artifact %q: %w", name, err))
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(hash, file, maxArtifactBytes+1)
		closeErr := file.Close()
		if copyErr != nil && !errors.Is(copyErr, io.EOF) {
			return artifactError(fmt.Errorf("hash artifact %q: %w", name, copyErr))
		}
		if closeErr != nil {
			return artifactError(fmt.Errorf("close artifact %q: %w", name, closeErr))
		}
		got := hex.EncodeToString(hash.Sum(nil))
		if got != expected {
			return artifactError(fmt.Errorf("artifact %q digest mismatch", name))
		}
	}
	return nil
}

// LoadAndVerifyRelease performs the complete manifest + artifact trust check
// for a local release directory. It is useful to platform launchers and keeps
// the order of checks explicit.
func LoadAndVerifyRelease(root, manifestPath, signaturePath string, roots map[string]ed25519.PublicKey) (ArtifactManifest, error) {
	raw, err := readBoundedFile(manifestPath, maxManifestBytes)
	if err != nil {
		return ArtifactManifest{}, artifactError(fmt.Errorf("read manifest: %w", err))
	}
	signature, err := readBoundedFile(signaturePath, ed25519.SignatureSize*2+128)
	if err != nil {
		return ArtifactManifest{}, artifactError(fmt.Errorf("read detached signature: %w", err))
	}
	manifest, err := VerifySignedManifest(raw, signature, roots)
	if err != nil {
		return ArtifactManifest{}, err
	}
	if err := VerifyArtifactSet(root, manifest); err != nil {
		return ArtifactManifest{}, err
	}
	return manifest, nil
}

// SignManifest is a helper for release tooling and tests. The returned
// signature is raw Ed25519 bytes; release artifacts may encode it as base64 or
// hex when transported, but verification always authenticates the same bytes.
func SignManifest(raw []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("manifest signing key has invalid length")
	}
	if _, err := ParseArtifactManifest(raw); err != nil {
		return nil, err
	}
	return ed25519.Sign(key, raw), nil
}

func decodeDetachedSignature(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SignatureSize {
		return append([]byte(nil), raw...), nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == ed25519.SignatureSize*2 {
		decoded, err := hex.DecodeString(string(trimmed))
		if err == nil {
			return decoded, nil
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("detached signature must be raw, lowercase/uppercase hex, or base64 Ed25519 bytes")
	}
	return decoded, nil
}

func artifactError(err error) error {
	return &InstallerError{Code: ExitArtifactVerification, Op: "artifact verification", Cause: err}
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file is not a regular non-symlink")
	}
	if info.Size() > limit {
		return nil, errors.New("file exceeds size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func secureJoin(root, name string) (string, error) {
	if err := validateArtifactName(name); err != nil {
		return "", err
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(cleanRoot, filepath.FromSlash(name))
	rel, err := filepath.Rel(cleanRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %q escapes artifact root", name)
	}
	return path, nil
}
