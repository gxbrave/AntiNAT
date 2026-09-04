package install

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
)

const ownershipManifestSchema = 1

// OwnedResource identifies one resource relative to an explicit root. Keeping
// the root beside the relative path prevents a manifest entry intended for
// /var/lib from being interpreted below /opt (or vice versa).
type OwnedResource struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

// OwnershipManifest is the installer-owned resource inventory. Its HMAC is
// over the canonical payload fields only; the key is held separately with
// owner-only permissions and is never included in the JSON.
type OwnershipManifest struct {
	SchemaVersion  int             `json:"schema_version"`
	InstallationID string          `json:"installation_id"`
	Resources      []OwnedResource `json:"resources"`
	HMAC           string          `json:"hmac"`
}

type ownershipPayload struct {
	SchemaVersion  int             `json:"schema_version"`
	InstallationID string          `json:"installation_id"`
	Resources      []OwnedResource `json:"resources"`
}

// NewInstallationID creates an opaque installation identifier used to bind a
// purge manifest to one installation.
func NewInstallationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// CreateOwnershipManifest writes a signed inventory atomically with mode 0600.
func CreateOwnershipManifest(path string, manifest OwnershipManifest, key []byte) error {
	if err := validateOwnershipManifest(manifest); err != nil {
		return err
	}
	if len(key) < 16 {
		return errors.New("ownership HMAC key is too short")
	}
	manifest.HMAC = ownershipHMAC(manifest, key)
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ownership manifest: %w", err)
	}
	return atomicWritePrivate(path, raw, 0o600)
}

// VerifyOwnershipManifest parses and authenticates a manifest without
// deleting anything.
func VerifyOwnershipManifest(path string, key []byte) (OwnershipManifest, error) {
	if len(key) < 16 {
		return OwnershipManifest{}, errors.New("ownership HMAC key is too short")
	}
	raw, err := readBoundedFile(path, 4<<20)
	if err != nil {
		return OwnershipManifest{}, fmt.Errorf("read ownership manifest: %w", err)
	}
	var manifest OwnershipManifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return OwnershipManifest{}, fmt.Errorf("decode ownership manifest: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return OwnershipManifest{}, errors.New("ownership manifest has trailing JSON values")
		}
		return OwnershipManifest{}, fmt.Errorf("ownership manifest has trailing data: %w", err)
	}
	if err := validateOwnershipManifest(manifest); err != nil {
		return OwnershipManifest{}, err
	}
	want := ownershipHMAC(manifest, key)
	got, err := hex.DecodeString(manifest.HMAC)
	if err != nil || len(got) != sha256.Size || !hmac.Equal(got, mustHex(want)) {
		return OwnershipManifest{}, errors.New("ownership manifest HMAC mismatch")
	}
	return manifest, nil
}

func mustHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func ownershipHMAC(manifest OwnershipManifest, key []byte) string {
	payload := ownershipPayload{
		SchemaVersion:  manifest.SchemaVersion,
		InstallationID: manifest.InstallationID,
		Resources:      append([]OwnedResource(nil), manifest.Resources...),
	}
	// Resources are ordered in the signed payload so an operator cannot reorder
	// entries and produce confusing evidence. CreateOwnershipManifest sorts a
	// copy via validateOwnershipManifest before this function is called.
	raw, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func validateOwnershipManifest(manifest OwnershipManifest) error {
	if manifest.SchemaVersion != ownershipManifestSchema {
		return fmt.Errorf("unsupported ownership manifest schema %d", manifest.SchemaVersion)
	}
	if manifest.InstallationID == "" || len(manifest.InstallationID) > 128 || strings.ContainsAny(manifest.InstallationID, "/\\\x00\r\n") {
		return errors.New("invalid ownership installation id")
	}
	if len(manifest.Resources) == 0 {
		return errors.New("ownership manifest has no resources")
	}
	seen := make(map[string]struct{}, len(manifest.Resources))
	for _, resource := range manifest.Resources {
		root, err := filepath.Abs(resource.Root)
		if err != nil || root == "." {
			return fmt.Errorf("invalid ownership root %q", resource.Root)
		}
		if filepath.Clean(root) != root {
			return fmt.Errorf("ownership root %q is not canonical", resource.Root)
		}
		if err := validateRelativeResource(resource.Path); err != nil {
			return err
		}
		key := root + "\x00" + resource.Path
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate ownership resource %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateRelativeResource(path string) error {
	if path == "" || pathpkg.IsAbs(path) || pathpkg.Clean(path) != path || path == "." || path == ".." {
		return fmt.Errorf("ownership resource %q is not a safe relative path", path)
	}
	if strings.ContainsAny(path, "\\:\x00") {
		return fmt.Errorf("ownership resource %q contains an unsafe character", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("ownership resource %q contains an unsafe component", path)
		}
	}
	return nil
}

// PurgeOptions controls a manifest-driven purge. Fallback resources are used
// only when the manifest is absent or fails authentication. They should be the
// compile-time allowlist returned by DefaultPurgeResources.
type PurgeOptions struct {
	ManifestPath string
	HMACKey      []byte
	Fallback     []OwnedResource
	// Allowed is the compile-time ownership allowlist. A verified manifest is
	// still untrusted input until every resource matches this list exactly.
	Allowed []OwnedResource
}

type PurgeResult struct {
	ManifestVerified bool
	UsedFallback     bool
	Removed          []OwnedResource
	Warnings         []string
	NoResidue        bool
}

// PurgeOwned removes only authenticated or fallback-owned resources. Missing
// entries are idempotent. A symlink/reparse point anywhere below a resource
// fails closed before that resource is removed.
func PurgeOwned(opts PurgeOptions) (PurgeResult, error) {
	var result PurgeResult
	if opts.ManifestPath == "" {
		return result, errors.New("purge manifest path is required")
	}
	manifest, err := VerifyOwnershipManifest(opts.ManifestPath, opts.HMACKey)
	resources := opts.Fallback
	if err == nil {
		result.ManifestVerified = true
		resources = manifest.Resources
		if len(opts.Allowed) == 0 {
			return result, errors.New("purge ownership allowlist is required for a verified manifest")
		}
		if err := resourcesWithinAllowlist(resources, opts.Allowed); err != nil {
			return result, err
		}
	} else {
		result.UsedFallback = true
		result.Warnings = append(result.Warnings, "ownership manifest was absent or invalid; only the compile-time fallback allowlist was used")
	}
	if len(resources) == 0 {
		return result, fmt.Errorf("purge has no safe resources: %w", err)
	}
	if err := validateResourceList(resources); err != nil {
		return result, err
	}
	// Delete children first, but keep deterministic ordering for evidence.
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Root != resources[j].Root {
			return resources[i].Root < resources[j].Root
		}
		return depth(resources[i].Path) > depth(resources[j].Path) || resources[i].Path > resources[j].Path
	})
	for _, resource := range resources {
		removed, err := removeOwnedResource(resource.Root, resource.Path)
		if err != nil {
			return result, fmt.Errorf("purge %s/%s: %w", resource.Root, resource.Path, err)
		}
		if removed {
			result.Removed = append(result.Removed, resource)
		}
	}
	result.NoResidue = true
	for _, resource := range resources {
		if exists, err := ownedResourceExists(resource.Root, resource.Path); err != nil {
			return result, err
		} else if exists {
			result.NoResidue = false
		}
	}
	return result, nil
}

func validateResourceList(resources []OwnedResource) error {
	if len(resources) == 0 {
		return errors.New("empty ownership resource list")
	}
	for _, resource := range resources {
		root, err := filepath.Abs(resource.Root)
		if err != nil || filepath.Clean(root) != root {
			return fmt.Errorf("invalid ownership root %q", resource.Root)
		}
		if err := validateRelativeResource(resource.Path); err != nil {
			return err
		}
	}
	return nil
}

func resourcesWithinAllowlist(resources, allowed []OwnedResource) error {
	if err := validateResourceList(allowed); err != nil {
		return fmt.Errorf("invalid purge ownership allowlist: %w", err)
	}
	allowedKeys := make(map[string]struct{}, len(allowed))
	for _, resource := range allowed {
		root, _ := filepath.Abs(resource.Root)
		allowedKeys[root+"\x00"+resource.Path] = struct{}{}
	}
	for _, resource := range resources {
		root, _ := filepath.Abs(resource.Root)
		if _, ok := allowedKeys[root+"\x00"+resource.Path]; !ok {
			return fmt.Errorf("ownership resource %q/%q is not in the compile-time allowlist", resource.Root, resource.Path)
		}
	}
	return nil
}

func depth(path string) int { return strings.Count(filepath.ToSlash(path), "/") }

// DefaultPurgeResources is intentionally narrow. It does not include arbitrary
// files under /etc, reverse-proxy configuration, TLS material or external
// volumes. A valid installation manifest may add only resources it created.
func DefaultPurgeResources(layout Layout) []OwnedResource {
	resources := []OwnedResource{
		{Root: layout.InstallDir, Path: "bin/antinat-agent"},
		{Root: layout.InstallDir, Path: "bin/antinat-controller"},
		{Root: layout.InstallDir, Path: "bin/antinat-hook-runner"},
		{Root: layout.DataDir, Path: "state.db"},
		{Root: layout.DataDir, Path: "node.key"},
		{Root: layout.DataDir, Path: "controller.db"},
		{Root: layout.DataDir, Path: "controller-keys"},
		{Root: layout.DataDir, Path: "terminal.marker"},
		{Root: layout.DataDir, Path: "agent.marker"},
		{Root: layout.DataDir, Path: "backups"},
		{Root: layout.DataDir, Path: "ownership-manifest.json"},
		{Root: layout.DataDir, Path: "ownership.key"},
		{Root: filepath.Dir(layout.ConfigFile), Path: "agent.conf"},
		{Root: layout.ServiceDir, Path: "antinat-agent.service"},
		{Root: layout.ServiceDir, Path: "antinat-controller.service"},
	}
	return resources
}

func atomicWritePrivate(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("private write path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".antinat-private-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncParent(path)
}

func syncParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
