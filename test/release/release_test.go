package release

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/install"
)

func TestReleaseSecurityBoundary(t *testing.T) {
	paths := []string{
		filepath.Join("..", "..", "scripts", "run-beta-gates.sh"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(raw)
		if strings.Contains(text, "curl | bash") || strings.Contains(text, "curl|bash") {
			t.Fatalf("%s contains an unsafe curl-to-shell pipeline", path)
		}
		if strings.Contains(text, "pull_request_target") {
			t.Fatalf("%s enables privileged fork execution", path)
		}
	}

	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflowText := string(workflow)
	if strings.Contains(workflowText, "--version '${{ inputs.version }}'") {
		t.Fatal("release workflow interpolates the version directly into shell quoting")
	}
	for _, required := range []string{
		`--version "$RELEASE_VERSION"`,
		"Verify candidate source identity",
		"source.commit_sha",
		"protected promotion job verified the detached Ed25519 signature",
		"release-evidence.log",
	} {
		if !strings.Contains(workflowText, required) {
			t.Fatalf("release workflow missing promotion safety check %q", required)
		}
	}
}

func TestBetaRunnerExecutesAvailableReleaseGates(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "run-beta-gates.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)
	if !strings.Contains(text, `-f "$repo_dir/test/browser/package.json"`) {
		t.Fatal("browser gate must be selected from the pinned package manifest")
	}
	if strings.Contains(text, `-d "$repo_dir/test/browser/node_modules"`) {
		t.Fatal("browser gate must not require preinstalled node_modules")
	}
	if !strings.Contains(text, "command -v node") || !strings.Contains(text, "command -v npm") {
		t.Fatal("browser gate must check for its runtime prerequisites")
	}
	if !strings.Contains(text, "govulncheck ./...") {
		t.Fatal("release runner must retain the vulnerability gate")
	}
}

func TestExactArtifactMetadata(t *testing.T) {
	releaseDir := os.Getenv("ANTINAT_RELEASE_DIR")
	if releaseDir == "" {
		t.Skip("P19 runner supplies an exact release directory for this check")
	}
	releaseDir, err := filepath.Abs(releaseDir)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(releaseDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read release manifest: %v", err)
	}
	manifest, err := install.ParseArtifactManifest(manifestRaw)
	if err != nil {
		t.Fatalf("parse release manifest: %v", err)
	}
	if err := install.VerifyArtifactSet(releaseDir, manifest); err != nil {
		t.Fatalf("verify exact release artifacts: %v", err)
	}

	for _, name := range []string{"antinat-agent-linux-amd64", "antinat-controller-linux-amd64"} {
		path := filepath.Join(releaseDir, name)
		output, err := exec.Command(path, "version").CombinedOutput()
		if err != nil {
			t.Fatalf("%s version: %v (%s)", name, err, output)
		}
		if !strings.Contains(string(output), "version=") || !strings.Contains(string(output), "commit=") {
			t.Fatalf("%s version output lacks build identity: %q", name, output)
		}
	}
}

func TestOptionalReleasePublicKeyIsEd25519(t *testing.T) {
	path := os.Getenv("ANTINAT_RELEASE_PUBLIC_KEY")
	if path == "" {
		t.Skip("release public key is optional for an unsigned local candidate")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("public key is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		t.Fatalf("public key type = %T, want Ed25519", key)
	}
}
