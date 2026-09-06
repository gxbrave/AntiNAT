package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// manifestEntry is one artifact entry in the frozen manifest.
type manifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// contractManifest is the frozen manifest schema.
type contractManifest struct {
	Schema            string          `json:"schema"`
	ContractRevision  string          `json:"contract_revision"`
	ValidationCommand string          `json:"validation_command"`
	Artifacts         []manifestEntry `json:"artifacts"`
}

// TestContractManifest verifies that test/contracts/manifest.json lists the
// SHA-256 of every frozen artifact and that each hash matches the file on
// disk. It also verifies completeness: every JSON fixture under the frozen
// testdata/fixtures directories and every frozen doc is present, so a
// silently-modified contract artifact is caught.
func TestContractManifest(t *testing.T) {
	root := repoRoot(t)
	manifestPath := filepath.Join(root, "test", "contracts", "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest.json missing: %v", err)
	}
	var m contractManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest.json parse: %v", err)
	}
	if m.Schema != "antinat.contracts/manifest/v1" {
		t.Fatalf("manifest schema must be antinat.contracts/manifest/v1, got %q", m.Schema)
	}
	if m.ContractRevision == "" {
		t.Fatal("contract_revision must not be empty (no placeholders)")
	}
	if m.ValidationCommand == "" {
		t.Fatal("validation_command must not be empty (no placeholders)")
	}
	if !strings.Contains(m.ValidationCommand, "go test ./test/contracts/...") {
		t.Fatalf("validation_command must be the frozen gate, got %q", m.ValidationCommand)
	}
	if len(m.Artifacts) == 0 {
		t.Fatal("manifest has no artifacts (no placeholders)")
	}

	// 1. Every listed artifact exists and its hash matches.
	listed := map[string]string{}
	for _, entry := range m.Artifacts {
		if entry.Path == "" || entry.SHA256 == "" {
			t.Fatalf("artifact entry with empty path or hash")
		}
		if _, dup := listed[entry.Path]; dup {
			t.Fatalf("duplicate artifact path %q", entry.Path)
		}
		listed[entry.Path] = entry.SHA256
		abs := filepath.Join(root, entry.Path)
		data, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("listed artifact %q missing: %v", entry.Path, err)
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != entry.SHA256 {
			t.Fatalf("artifact %q hash mismatch: manifest %s, file %s", entry.Path, entry.SHA256, got)
		}
	}

	// 2. Completeness: every frozen file must be listed.
	expected := collectFrozenManifestFiles(root)
	for _, rel := range expected {
		if _, ok := listed[rel]; !ok {
			t.Fatalf("frozen artifact %q not present in manifest", rel)
		}
	}
	// 3. No extra entries outside the frozen set.
	for rel := range listed {
		if !isFrozenManifestFile(rel) {
			t.Fatalf("manifest lists non-frozen path %q", rel)
		}
	}
}

// collectFrozenManifestFiles returns the sorted relative paths of every file
// that must appear in the manifest.
func collectFrozenManifestFiles(root string) []string {
	frozenPaths := []string{
		"docs/protocol.md",
		"docs/state-model.md",
		"docs/installer-contract.md",
		"docs/test-strategy.md",
		"docs/error-codes.md",
		"api/openapi.yaml",
	}
	frozenDirs := []string{
		filepath.Join("internal", "protocol", "testdata"),
		filepath.Join("test", "fixtures", "compat"),
		filepath.Join("test", "fixtures", "installer-contract"),
		filepath.Join("test", "contracts", "testdata", "state-model"),
	}
	var out []string
	for _, rel := range frozenPaths {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			out = append(out, rel)
		}
	}
	for _, dir := range frozenDirs {
		_ = filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() || !strings.HasSuffix(path, ".json") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr == nil {
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	// sort
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func isFrozenManifestFile(rel string) bool {
	for _, p := range []string{
		"docs/protocol.md",
		"docs/state-model.md",
		"docs/installer-contract.md",
		"docs/test-strategy.md",
		"docs/error-codes.md",
		"api/openapi.yaml",
	} {
		if rel == p {
			return true
		}
	}
	for _, dir := range []string{
		"internal/protocol/testdata/",
		"test/fixtures/compat/",
		"test/fixtures/installer-contract/",
		"test/contracts/testdata/state-model/",
	} {
		if strings.HasPrefix(rel, dir) && strings.HasSuffix(rel, ".json") {
			return true
		}
	}
	return false
}
