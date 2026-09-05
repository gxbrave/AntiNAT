package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/install"
)

func TestVerifyReleaseEvidenceAcceptsSignedCandidate(t *testing.T) {
	bundle, publicKey := makeReleaseBundle(t, true)
	t.Setenv("ANTINAT_TEST_MODE", "1")
	report, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{
		PublicKeyPath: publicKey,
		AllowTestRoot: true,
	})
	if err != nil {
		t.Fatalf("verifyReleaseEvidence() error = %v", err)
	}
	if !report.Signed || report.Promotable {
		t.Fatalf("report = %+v, want signed non-promotable candidate", report)
	}
}

func TestVerifyReleaseEvidenceRequiresExplicitPromotionApproval(t *testing.T) {
	bundle, publicKey := makeReleaseBundle(t, true)
	t.Setenv("ANTINAT_TEST_MODE", "1")
	if _, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{
		PublicKeyPath:    publicKey,
		AllowTestRoot:    true,
		RequirePromotion: true,
	}); err == nil || !strings.Contains(err.Error(), "not promotable") {
		t.Fatalf("promotion verification error = %v, want approval rejection", err)
	}
}

func TestVerifyReleaseEvidenceRejectsArtifactMutation(t *testing.T) {
	bundle, publicKey := makeReleaseBundle(t, true)
	if err := os.WriteFile(filepath.Join(bundle.release, "antinat-agent-linux-amd64"), []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTINAT_TEST_MODE", "1")
	if _, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{
		PublicKeyPath: publicKey,
		AllowTestRoot: true,
	}); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("mutation verification error = %v, want digest mismatch", err)
	}
}

func TestVerifyReleaseEvidenceRejectsGateDigestMismatch(t *testing.T) {
	bundle, publicKey := makeReleaseBundle(t, true)
	recordPath := filepath.Join(bundle.evidence, "release.json")
	var record releaseEvidence
	decodeJSONFile(t, recordPath, &record)
	record.Gates[0].ArtifactDigest = "sha256:" + strings.Repeat("0", 64)
	writeJSONFile(t, recordPath, record)

	t.Setenv("ANTINAT_TEST_MODE", "1")
	if _, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{
		PublicKeyPath: publicKey,
		AllowTestRoot: true,
	}); err == nil || !strings.Contains(err.Error(), "does not match manifest digest") {
		t.Fatalf("digest verification error = %v, want gate digest mismatch", err)
	}
}

func TestVerifyReleaseEvidenceRejectsGateEvidenceMissingFromBundle(t *testing.T) {
	bundle, publicKey := makeReleaseBundle(t, true)
	recordPath := filepath.Join(bundle.evidence, "release.json")
	var record releaseEvidence
	decodeJSONFile(t, recordPath, &record)
	record.Gates[0].Evidence = []string{"missing-gate.log"}
	writeJSONFile(t, recordPath, record)

	t.Setenv("ANTINAT_TEST_MODE", "1")
	if _, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{
		PublicKeyPath: publicKey,
		AllowTestRoot: true,
	}); err == nil || !strings.Contains(err.Error(), "missing-gate.log") {
		t.Fatalf("gate evidence verification error = %v, want missing evidence rejection", err)
	}
}

func TestVerifyReleaseEvidenceAllowsUnsignedLocalCandidateOnly(t *testing.T) {
	bundle, _ := makeReleaseBundle(t, false)
	recordPath := filepath.Join(bundle.evidence, "release.json")
	var record releaseEvidence
	decodeJSONFile(t, recordPath, &record)
	record.SignatureStatus = "SKIPPED"
	writeJSONFile(t, recordPath, record)

	report, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{})
	if err != nil {
		t.Fatalf("verifyReleaseEvidence() error = %v", err)
	}
	if report.Signed || report.Promotable {
		t.Fatalf("report = %+v, want unsigned non-promotable candidate", report)
	}
	if _, err := verifyReleaseEvidence(bundle.evidence, releaseVerifierOptions{RequirePromotion: true}); err == nil {
		t.Fatal("unsigned candidate passed promotion verification")
	}
}

type releaseBundle struct {
	evidence string
	release  string
}

func makeReleaseBundle(t *testing.T, signed bool) (releaseBundle, string) {
	t.Helper()
	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	releaseDir := filepath.Join(root, "release")
	if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(releaseDir, 0o700); err != nil {
		t.Fatal(err)
	}

	artifactContents := map[string][]byte{
		"antinat-agent-linux-amd64": []byte("agent release bytes\n"),
		"source.json":               []byte(`{"commit_sha":"0123456789abcdef0123456789abcdef01234567"}` + "\n"),
		"sbom.cdx.json":             []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"AntiNAT","version":"v1.0.0-beta.1"}},"components":[]}` + "\n"),
	}
	for name, data := range artifactContents {
		if err := os.WriteFile(filepath.Join(releaseDir, name), data, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	names := make([]string, 0, len(artifactContents))
	for name := range artifactContents {
		names = append(names, name)
	}
	sort.Strings(names)
	var checksums strings.Builder
	artifactDigests := make(map[string]string, len(artifactContents)+1)
	for _, name := range names {
		sum := sha256.Sum256(artifactContents[name])
		digest := hex.EncodeToString(sum[:])
		artifactDigests[name] = digest
		checksums.WriteString(digest + "  " + name + "\n")
	}
	checksumBytes := []byte(checksums.String())
	if err := os.WriteFile(filepath.Join(releaseDir, "checksums.txt"), checksumBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	checksumSum := sha256.Sum256(checksumBytes)
	artifactDigests["checksums.txt"] = hex.EncodeToString(checksumSum[:])

	manifestRaw, err := json.Marshal(install.ArtifactManifest{
		SchemaVersion:      install.ArtifactManifestSchema,
		Release:            "v1.0.0-beta.1",
		Artifacts:          artifactDigests,
		TrustRoot:          "test-root",
		SignatureAlgorithm: "ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	publicKeyPath := ""
	if signed {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := install.SignManifest(manifestRaw, private)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(releaseDir, "manifest.sig"), signature, 0o600); err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		publicKeyPath = filepath.Join(root, "test-root.pub")
		if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(evidenceDir, "gate.log"), []byte("release gate completed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	buildStart := now.Add(-5 * time.Minute)
	buildFinish := now.Add(-4 * time.Minute)
	testStart := now.Add(-3 * time.Minute)
	commit := "0123456789abcdef0123456789abcdef01234567"
	tree := "89abcdef0123456789abcdef0123456789abcdef"
	manifestSum := sha256.Sum256(manifestRaw)
	digest := "sha256:" + hex.EncodeToString(manifestSum[:])
	gates := make([]releaseGate, 0, len(requiredReleaseGates))
	for _, id := range requiredReleaseGates {
		gates = append(gates, releaseGate{
			ID:             id,
			Result:         "PASS",
			Required:       true,
			Command:        "fixture gate " + id,
			ArtifactDigest: digest,
			Evidence:       []string{"gate.log"},
			Summary:        "fixture pass",
		})
	}
	artifactNames := make([]string, 0, len(artifactDigests))
	for name := range artifactDigests {
		artifactNames = append(artifactNames, name)
	}
	sort.Strings(artifactNames)
	record := releaseEvidence{
		SchemaVersion:     releaseEvidenceSchema,
		Release:           "v1.0.0-beta.1",
		Status:            "SUPPORTED_WITH_LIMITS",
		ArtifactDirectory: "../release",
		Manifest:          "manifest.json",
		Signature:         "manifest.sig",
		ManifestSHA256:    digest,
		Source: releaseSource{
			Module:  "github.com/gxbrave/AntiNAT",
			Commit:  commit,
			Tree:    tree,
			Go:      "go1.26.5",
			BuiltAt: buildStart.Format(time.RFC3339),
		},
		Build: releaseBuild{
			Count:        1,
			StartedAt:    buildStart.Format(time.RFC3339),
			FinishedAt:   buildFinish.Format(time.RFC3339),
			TestStarted:  testStart.Format(time.RFC3339),
			TestFinished: now.Format(time.RFC3339),
		},
		Approval:        releaseApproval{Approved: false, Approver: "PENDING"},
		Gates:           gates,
		KnownLimits:     []string{"fixture is not a production release"},
		Evidence:        []string{"gate.log"},
		ArtifactNames:   artifactNames,
		SignatureStatus: map[bool]string{true: "PASS", false: "SKIPPED"}[signed],
		SBOMStatus:      "PASS",
	}
	writeJSONFile(t, filepath.Join(evidenceDir, "release.json"), record)
	return releaseBundle{evidence: evidenceDir, release: releaseDir}, publicKeyPath
}

func decodeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
