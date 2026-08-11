package contracts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenAPIAndErrorCodeCoverage validates the frozen API contract:
// api/openapi.yaml is well-formed OpenAPI 3.x, all normative routes exist,
// ETag/If-Match and Idempotency-Key are enforced on the frozen operations,
// pagination/cursor and SSE Last-Event-ID are present, and error-code
// coverage is bidirectional with docs/error-codes.md.
//
// The validator is a Python script (test/contracts/validate_openapi.py)
// because go.mod is frozen by P01 and the module has no YAML dependency;
// python3 + PyYAML is already a project toolchain dependency (make check).
func TestOpenAPIAndErrorCodeCoverage(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "test", "contracts", "validate_openapi.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("validator script missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "api", "openapi.yaml")); err != nil {
		t.Fatalf("api/openapi.yaml missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "error-codes.md")); err != nil {
		t.Fatalf("docs/error-codes.md missing: %v", err)
	}

	cmd := exec.Command("python3", script, root)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		t.Fatalf("OpenAPI/error-code validation failed:\n%s", text)
	}
	t.Log(text)
}
