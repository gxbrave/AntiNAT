// Command verify-release-evidence validates a P19 release evidence bundle.
//
// The verifier intentionally authenticates the exact manifest bytes on disk
// before checking any artifact. It can validate an unsigned local candidate,
// but promotion mode requires the pinned release key, a complete PASS gate
// set, and an explicit independent approval record.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/install"
)

const (
	releaseEvidenceSchema = "antinat.release-evidence/v1"
	defaultTrustRootID    = "release-key-2026"
	maxReleaseEvidence    = 4 << 20
	maxReleaseMetadata    = 1 << 20
)

var (
	releaseVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$`)
	sha256Pattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	shaPattern            = regexp.MustCompile(`^[0-9a-f]{40}$`)
	checksumLinePattern   = regexp.MustCompile(`^([0-9a-f]{64})  ([^\r\n]+)$`)
)

type releaseEvidence struct {
	SchemaVersion     string          `json:"schema_version"`
	Release           string          `json:"release"`
	Status            string          `json:"status"`
	ArtifactDirectory string          `json:"artifact_directory"`
	Manifest          string          `json:"manifest"`
	Signature         string          `json:"signature"`
	ManifestSHA256    string          `json:"manifest_sha256"`
	Source            releaseSource   `json:"source"`
	Build             releaseBuild    `json:"build"`
	Approval          releaseApproval `json:"approval"`
	Gates             []releaseGate   `json:"gates"`
	KnownLimits       []string        `json:"known_limits"`
	Evidence          []string        `json:"evidence"`
	ArtifactNames     []string        `json:"artifact_names"`
	SignatureStatus   string          `json:"signature_status"`
	SBOMStatus        string          `json:"sbom_status"`
}

type releaseSource struct {
	Module  string `json:"module"`
	Commit  string `json:"commit_sha"`
	Tree    string `json:"tree_sha"`
	Go      string `json:"go_version"`
	BuiltAt string `json:"built_at"`
}

type releaseBuild struct {
	Count        int    `json:"count"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	TestStarted  string `json:"test_started_at"`
	TestFinished string `json:"test_finished_at"`
}

type releaseApproval struct {
	Approved   bool   `json:"approved"`
	Approver   string `json:"approver"`
	RecordedAt string `json:"recorded_at"`
}

type releaseGate struct {
	ID             string   `json:"id"`
	Result         string   `json:"result"`
	Required       bool     `json:"required"`
	Command        string   `json:"command"`
	ArtifactDigest string   `json:"artifact_digest"`
	Evidence       []string `json:"evidence"`
	Summary        string   `json:"summary"`
}

type releaseVerifierOptions struct {
	RequirePromotion bool
	PublicKeyPath    string
	AllowTestRoot    bool
}

type releaseVerificationReport struct {
	Promotable       bool
	Signed           bool
	ManifestDigest   string
	ArtifactCount    int
	SignatureMessage string
}

var requiredReleaseGates = []string{
	"exact-build",
	"artifact-integrity",
	"signature",
	"functional-e2e",
	"security",
	"install-upgrade-purge",
	"real-wan",
	"platform-matrix",
	"soak",
}

func main() {
	flags := flag.NewFlagSet("verify-release-evidence", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	requirePromotion := flags.Bool("require-promotion", false, "require a signed, fully approved release")
	publicKey := flags.String("public-key", "", "override the pinned public key (test use only with --allow-test-root)")
	allowTestRoot := flags.Bool("allow-test-root", false, "allow an explicit non-production trust root for local candidates")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "RELEASE_EVIDENCE_USAGE: usage: verify-release-evidence [--require-promotion] <evidence-dir>")
		os.Exit(2)
	}
	report, err := verifyReleaseEvidence(flags.Arg(0), releaseVerifierOptions{
		RequirePromotion: *requirePromotion,
		PublicKeyPath:    *publicKey,
		AllowTestRoot:    *allowTestRoot,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", flags.Arg(0), err)
		os.Exit(1)
	}
	if report.Signed {
		fmt.Printf("PASS %s: release evidence is structurally valid and manifest signature verified (%s)\n", flags.Arg(0), report.ManifestDigest)
	} else {
		fmt.Printf("SUPPORTED_WITH_LIMITS %s: release candidate is structurally valid but unsigned (%s)\n", flags.Arg(0), report.ManifestDigest)
	}
}

func verifyReleaseEvidence(evidenceDir string, options releaseVerifierOptions) (releaseVerificationReport, error) {
	var report releaseVerificationReport
	evidenceDir, err := canonicalDirectory(evidenceDir)
	if err != nil {
		return report, fmt.Errorf("evidence directory: %w", err)
	}
	recordPath := filepath.Join(evidenceDir, "release.json")
	recordRaw, err := readBoundedRegular(recordPath, maxReleaseEvidence)
	if err != nil {
		return report, fmt.Errorf("release record: %w", err)
	}
	record, err := decodeReleaseEvidence(recordRaw)
	if err != nil {
		return report, err
	}
	if err := validateReleaseEvidenceRecord(record); err != nil {
		return report, err
	}

	artifactDir, err := safeArtifactDirectory(evidenceDir, record.ArtifactDirectory)
	if err != nil {
		return report, fmt.Errorf("artifact directory: %w", err)
	}
	manifestPath, err := safeRelativePath(artifactDir, record.Manifest)
	if err != nil {
		return report, fmt.Errorf("manifest path: %w", err)
	}
	manifestRaw, err := readBoundedRegular(manifestPath, maxReleaseMetadata)
	if err != nil {
		return report, fmt.Errorf("manifest: %w", err)
	}
	manifestSum := sha256.Sum256(manifestRaw)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])
	if record.ManifestSHA256 != manifestDigest {
		return report, fmt.Errorf("manifest digest mismatch: record=%s actual=%s", record.ManifestSHA256, manifestDigest)
	}
	report.ManifestDigest = manifestDigest

	manifest, err := install.ParseArtifactManifest(manifestRaw)
	if err != nil {
		return report, fmt.Errorf("parse artifact manifest: %w", err)
	}
	if manifest.Release != record.Release {
		return report, fmt.Errorf("manifest release %q does not match evidence release %q", manifest.Release, record.Release)
	}
	if err := validateArtifactLeaves(manifest.Artifacts); err != nil {
		return report, err
	}
	if err := install.VerifyArtifactSet(artifactDir, manifest); err != nil {
		return report, fmt.Errorf("artifact set: %w", err)
	}
	if err := validateChecksums(artifactDir, manifest); err != nil {
		return report, err
	}
	if err := validateSBOM(artifactDir, manifest, record.Release); err != nil {
		return report, err
	}
	if err := validateArtifactNamesMatch(record.ArtifactNames, manifest.Artifacts); err != nil {
		return report, err
	}
	if err := validateEvidenceFiles(evidenceDir, record.Evidence); err != nil {
		return report, err
	}

	signaturePath, sigPresent, err := optionalSafeEvidencePath(artifactDir, record.Signature)
	if err != nil {
		return report, fmt.Errorf("signature path: %w", err)
	}
	if sigPresent {
		signature, readErr := readBoundedRegular(signaturePath, 512)
		if readErr != nil {
			return report, fmt.Errorf("signature: %w", readErr)
		}
		if options.PublicKeyPath != "" && !options.AllowTestRoot {
			return report, errors.New("public-key override requires --allow-test-root")
		}
		keyPath, keyErr := resolvePublicKeyPath(evidenceDir, options.PublicKeyPath)
		if keyErr != nil {
			return report, keyErr
		}
		if manifest.TrustRoot != defaultTrustRootID && !options.AllowTestRoot {
			return report, fmt.Errorf("manifest trust root %q is not the pinned production root", manifest.TrustRoot)
		}
		publicKey, keyErr := loadPublicKey(keyPath)
		if keyErr != nil {
			return report, fmt.Errorf("public key: %w", keyErr)
		}
		if _, verifyErr := install.VerifySignedManifest(manifestRaw, signature, map[string]ed25519.PublicKey{
			manifest.TrustRoot: publicKey,
		}); verifyErr != nil {
			return report, fmt.Errorf("manifest signature: %w", verifyErr)
		}
		report.Signed = true
		report.SignatureMessage = "verified"
		if record.SignatureStatus != "PASS" {
			return report, fmt.Errorf("signature is present and verified but signature_status is %q", record.SignatureStatus)
		}
	} else {
		report.SignatureMessage = "missing"
		if record.SignatureStatus != "SKIPPED" {
			return report, errors.New("signature is missing but signature_status is not SKIPPED")
		}
	}

	report.ArtifactCount = len(manifest.Artifacts)
	report.Promotable = isPromotable(record, report.Signed)
	if options.RequirePromotion && !report.Promotable {
		return report, errors.New("release is not promotable: require a verified signature, PASS required gates, and an explicit independent approval")
	}
	return report, nil
}

func decodeReleaseEvidence(raw []byte) (releaseEvidence, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record releaseEvidence
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode release record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return record, errors.New("release record contains multiple JSON values")
		}
		return record, fmt.Errorf("release record trailing data: %w", err)
	}
	return record, nil
}

func validateReleaseEvidenceRecord(record releaseEvidence) error {
	if record.SchemaVersion != releaseEvidenceSchema {
		return fmt.Errorf("schema_version must be %q", releaseEvidenceSchema)
	}
	if !releaseVersionPattern.MatchString(record.Release) {
		return fmt.Errorf("release %q is not a beta version", record.Release)
	}
	if record.Status != "PASS" && record.Status != "SUPPORTED_WITH_LIMITS" && record.Status != "NO_GO" && record.Status != "FAIL" {
		return fmt.Errorf("invalid release status %q", record.Status)
	}
	if record.ArtifactDirectory == "" || filepath.IsAbs(record.ArtifactDirectory) || strings.ContainsAny(record.ArtifactDirectory, "\\\x00") {
		return errors.New("artifact_directory must be a relative path")
	}
	if record.Manifest == "" || filepath.IsAbs(record.Manifest) || strings.ContainsAny(record.Manifest, "\\\x00") {
		return errors.New("manifest must be a relative path")
	}
	if record.Signature == "" || filepath.IsAbs(record.Signature) || strings.ContainsAny(record.Signature, "\\\x00") {
		return errors.New("signature must be a relative path")
	}
	if !sha256Pattern.MatchString(record.ManifestSHA256) {
		return errors.New("manifest_sha256 must be sha256:<64 lowercase hex characters>")
	}
	if record.Source.Module == "" || record.Source.Module != "github.com/gxbrave/AntiNAT" {
		return errors.New("source.module is not the approved module")
	}
	if !shaPattern.MatchString(record.Source.Commit) || !shaPattern.MatchString(record.Source.Tree) {
		return errors.New("source commit_sha and tree_sha must be full lowercase Git identities")
	}
	for _, timestamp := range []struct {
		name  string
		value string
	}{
		{"source.built_at", record.Source.BuiltAt},
		{"build.started_at", record.Build.StartedAt},
		{"build.finished_at", record.Build.FinishedAt},
		{"build.test_started_at", record.Build.TestStarted},
		{"build.test_finished_at", record.Build.TestFinished},
	} {
		if _, err := parseTimestamp(timestamp.value); err != nil {
			return fmt.Errorf("%s: %w", timestamp.name, err)
		}
	}
	if record.Build.Count != 1 {
		return fmt.Errorf("build.count must be exactly 1, got %d", record.Build.Count)
	}
	started, _ := parseTimestamp(record.Build.StartedAt)
	finished, _ := parseTimestamp(record.Build.FinishedAt)
	testStarted, _ := parseTimestamp(record.Build.TestStarted)
	testFinished, _ := parseTimestamp(record.Build.TestFinished)
	if finished.Before(started) || testStarted.Before(finished) || testFinished.Before(testStarted) {
		return errors.New("build/test timestamps are out of order")
	}
	if record.SignatureStatus != "PASS" && record.SignatureStatus != "SKIPPED" {
		return fmt.Errorf("invalid signature_status %q", record.SignatureStatus)
	}
	if record.SBOMStatus != "PASS" && record.SBOMStatus != "SUPPORTED_WITH_LIMITS" && record.SBOMStatus != "SKIPPED" {
		return fmt.Errorf("invalid sbom_status %q", record.SBOMStatus)
	}
	if len(record.Gates) == 0 {
		return errors.New("gates must not be empty")
	}
	seen := make(map[string]bool, len(record.Gates))
	for _, gate := range record.Gates {
		if gate.ID == "" || seen[gate.ID] {
			return fmt.Errorf("gate id %q is empty or duplicated", gate.ID)
		}
		seen[gate.ID] = true
		if gate.Result != "PASS" && gate.Result != "SUPPORTED_WITH_LIMITS" && gate.Result != "NO_GO" && gate.Result != "FAIL" {
			return fmt.Errorf("gate %q has invalid result %q", gate.ID, gate.Result)
		}
		if strings.TrimSpace(gate.Command) == "" || strings.TrimSpace(gate.Summary) == "" || !sha256Pattern.MatchString(gate.ArtifactDigest) {
			return fmt.Errorf("gate %q has incomplete command, summary, or artifact digest", gate.ID)
		}
		if len(gate.Evidence) == 0 {
			return fmt.Errorf("gate %q has no evidence paths", gate.ID)
		}
		for _, path := range gate.Evidence {
			if strings.TrimSpace(path) == "" || filepath.IsAbs(path) || strings.ContainsAny(path, "\\\x00") {
				return fmt.Errorf("gate %q has an unsafe evidence path", gate.ID)
			}
		}
	}
	for _, required := range requiredReleaseGates {
		if !seen[required] {
			return fmt.Errorf("required gate %q is missing", required)
		}
	}
	if record.ApproverPlaceholder() && record.Approval.Approved {
		return errors.New("approval uses a placeholder approver")
	}
	if record.Approval.Approved {
		if strings.TrimSpace(record.Approval.Approver) == "" {
			return errors.New("approved release has no approver")
		}
		if _, err := parseTimestamp(record.Approval.RecordedAt); err != nil {
			return fmt.Errorf("approval.recorded_at: %w", err)
		}
	}
	for _, limit := range record.KnownLimits {
		if strings.TrimSpace(limit) == "" {
			return errors.New("known_limits contains an empty value")
		}
	}
	return nil
}

func (record releaseEvidence) ApproverPlaceholder() bool {
	switch strings.ToUpper(strings.TrimSpace(record.Approval.Approver)) {
	case "", "REQUIRED", "PENDING", "UNKNOWN", "TODO", "TBD":
		return true
	default:
		return false
	}
}

func parseTimestamp(value string) (time.Time, error) {
	if value == "" || strings.HasPrefix(value, "0000-") {
		return time.Time{}, errors.New("must be a non-zero RFC3339 timestamp")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("must be RFC3339: %w", err)
	}
	return parsed, nil
}

func validateArtifactLeaves(artifacts map[string]string) error {
	seen := make(map[string]string, len(artifacts))
	for name := range artifacts {
		leaf := filepath.Base(filepath.FromSlash(name))
		if prior, ok := seen[leaf]; ok && prior != name {
			return fmt.Errorf("artifact names collide after installer extraction: %q and %q", prior, name)
		}
		seen[leaf] = name
	}
	return nil
}

func validateChecksums(root string, manifest install.ArtifactManifest) error {
	checksumName := ""
	for name := range manifest.Artifacts {
		if filepath.Base(filepath.FromSlash(name)) == "checksums.txt" {
			if checksumName != "" {
				return errors.New("manifest contains multiple checksums.txt artifacts")
			}
			checksumName = name
		}
	}
	if checksumName == "" {
		return errors.New("manifest must include checksums.txt")
	}
	path := filepath.Join(root, filepath.FromSlash(checksumName))
	raw, err := readBoundedRegular(path, maxReleaseMetadata)
	if err != nil {
		return fmt.Errorf("checksums.txt: %w", err)
	}
	entries := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		match := checksumLinePattern.FindStringSubmatch(line)
		if len(match) != 3 {
			return fmt.Errorf("checksums.txt has malformed line %q", line)
		}
		if _, exists := entries[match[2]]; exists {
			return fmt.Errorf("checksums.txt duplicates %q", match[2])
		}
		entries[match[2]] = match[1]
	}
	for name, expected := range manifest.Artifacts {
		if name == checksumName {
			continue
		}
		if got, ok := entries[name]; !ok || got != expected {
			return fmt.Errorf("checksums.txt does not bind artifact %q", name)
		}
	}
	for name := range entries {
		if _, ok := manifest.Artifacts[name]; !ok {
			return fmt.Errorf("checksums.txt contains undeclared artifact %q", name)
		}
	}
	return nil
}

func validateSBOM(root string, manifest install.ArtifactManifest, release string) error {
	var sbomName string
	for name := range manifest.Artifacts {
		if strings.HasSuffix(strings.ToLower(name), ".cdx.json") || strings.HasSuffix(strings.ToLower(name), ".spdx.json") {
			if sbomName != "" {
				return errors.New("manifest contains multiple SBOM files")
			}
			sbomName = name
		}
	}
	if sbomName == "" {
		return errors.New("manifest must include a CycloneDX or SPDX SBOM")
	}
	raw, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(sbomName)), maxReleaseMetadata)
	if err != nil {
		return fmt.Errorf("SBOM: %w", err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return fmt.Errorf("SBOM is not JSON: %w", err)
	}
	if strings.HasSuffix(strings.ToLower(sbomName), ".cdx.json") {
		if object["bomFormat"] != "CycloneDX" || object["specVersion"] == nil {
			return errors.New("CycloneDX SBOM has no bomFormat/specVersion")
		}
	}
	if component, ok := object["metadata"].(map[string]any); ok {
		if rootComponent, ok := component["component"].(map[string]any); ok {
			if version, ok := rootComponent["version"].(string); ok && version != release {
				return fmt.Errorf("SBOM version %q does not match release %q", version, release)
			}
		}
	}
	return nil
}

func validateArtifactNamesMatch(want []string, artifacts map[string]string) error {
	if len(want) != len(artifacts) {
		return fmt.Errorf("artifact_names count %d does not match manifest count %d", len(want), len(artifacts))
	}
	seen := make(map[string]bool, len(want))
	for _, name := range want {
		if seen[name] {
			return fmt.Errorf("artifact_names duplicates %q", name)
		}
		seen[name] = true
		if _, ok := artifacts[name]; !ok {
			return fmt.Errorf("artifact_names contains undeclared artifact %q", name)
		}
	}
	return nil
}

func validateEvidenceFiles(root string, paths []string) error {
	for _, relative := range paths {
		path, err := safeRelativePath(root, relative)
		if err != nil {
			return fmt.Errorf("evidence path %q: %w", relative, err)
		}
		if _, err := readBoundedRegular(path, maxReleaseEvidence); err != nil {
			return fmt.Errorf("evidence path %q: %w", relative, err)
		}
	}
	return nil
}

func isPromotable(record releaseEvidence, signed bool) bool {
	if record.Status != "PASS" || !signed || !record.Approval.Approved || record.ApproverPlaceholder() {
		return false
	}
	for _, gate := range record.Gates {
		if gate.Required && gate.Result != "PASS" {
			return false
		}
	}
	return true
}

func resolvePublicKeyPath(evidenceDir, override string) (string, error) {
	if override != "" {
		if os.Getenv("ANTINAT_TEST_MODE") != "1" {
			return "", errors.New("public-key override requires ANTINAT_TEST_MODE=1")
		}
		if filepath.IsAbs(override) {
			return override, nil
		}
		return filepath.Abs(override)
	}
	root, err := findRepositoryRoot(evidenceDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "deploy", "trust", "release-ed25519.pub"), nil
}

func findRepositoryRoot(start string) (string, error) {
	path, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
			return path, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", errors.New("repository root with go.mod was not found")
		}
		path = parent
	}
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readBoundedRegular(path, 4096)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key must be a PEM PUBLIC KEY")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not Ed25519")
	}
	return publicKey, nil
}

func canonicalDirectory(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("must be a regular directory, not a symlink")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return "", errors.New("must be a canonical directory without symlink resolution")
	}
	return abs, nil
}

func safeEvidencePath(evidenceDir, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsAny(relative, "\\\x00") {
		return "", errors.New("must be a safe relative path")
	}
	bundleRoot := filepath.Dir(evidenceDir)
	path := filepath.Join(evidenceDir, filepath.FromSlash(relative))
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(bundleRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path escapes the release bundle")
	}
	return path, nil
}

func safeArtifactDirectory(evidenceDir, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsAny(relative, "\\\x00") {
		return "", errors.New("must be a relative artifact directory")
	}
	path, err := filepath.Abs(filepath.Join(evidenceDir, filepath.FromSlash(relative)))
	if err != nil {
		return "", err
	}
	if filepath.Base(path) != "release" {
		return "", errors.New("artifact directory must end in release")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("artifact directory must be a regular non-symlink directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("artifact directory must be canonical without symlink resolution")
	}
	return path, nil
}

func safeRelativePath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsAny(relative, "\\\x00") {
		return "", errors.New("must be a safe relative path")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path escapes its root")
	}
	return path, nil
}

func optionalSafeEvidencePath(root, relative string) (string, bool, error) {
	path, err := safeRelativePath(root, relative)
	if err != nil {
		return "", false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, false, nil
	}
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false, errors.New("path is not a regular non-symlink file")
	}
	return path, true, nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file is not a regular non-symlink file")
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

func currentGitIdentity(root string) (string, string, error) {
	commit := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	commitOut, err := commit.Output()
	if err != nil {
		return "", "", err
	}
	tree := exec.Command("git", "-C", root, "rev-parse", "HEAD^{tree}")
	treeOut, err := tree.Output()
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(commitOut)), strings.TrimSpace(string(treeOut)), nil
}

func sortedArtifactNames(artifacts map[string]string) []string {
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
