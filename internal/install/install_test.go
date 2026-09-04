package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseRejectsLiteralAndUnknownTokenArguments(t *testing.T) {
	valid, err := Parse([]string{"install", "--controller-endpoint", "https://controller.example", "--token-fd", "3"})
	if err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if valid.TokenFD != 3 || valid.ControllerEndpoint != "https://controller.example" {
		t.Fatalf("parsed options = %+v", valid)
	}
	for _, args := range [][]string{
		{"install", "--token", "secret"},
		{"install", "--token-value=secret"},
		{"install", "--magic-token-inline", "secret"},
		{"install", "-t", "secret"},
		{"install", "--token-fd"},
		{"install", "--token-fd", "2"},
		{"install", "--token-fd", "3", "--token-file", "/tmp/token"},
		{"install", "--help", "secret"},
	} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("Parse(%q) accepted forbidden input", args)
		} else if CodeOf(err) != ExitUsageError {
			t.Fatalf("Parse(%q) code = %d, want usage", args, CodeOf(err))
		}
	}
	if _, err := Parse([]string{"--version"}); err != nil {
		t.Fatalf("version parse: %v", err)
	}
}

func TestTokenFileIsStrictAndIdentityBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("enroll-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := OpenTokenInput(Options{Command: CommandInstall, TokenFile: path})
	if err != nil {
		t.Fatalf("open token: %v", err)
	}
	if input.Token() != "enroll-secret" {
		t.Fatalf("token = %q", input.Token())
	}
	if err := input.Commit(); err != nil {
		t.Fatalf("commit token: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token after commit: err=%v", err)
	}

	if err := os.WriteFile(path, []byte("old-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err = OpenTokenInput(Options{Command: CommandInstall, TokenFile: path})
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := input.Commit(); err == nil {
		t.Fatal("Commit accepted a replaced token file")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new-secret" {
		t.Fatalf("replacement token changed: %q err=%v", got, err)
	}
	_ = input.Close()

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTokenInput(Options{Command: CommandInstall, TokenFile: path}); err == nil {
		t.Fatal("opened a non-0600 token file")
	}
}

func TestTokenFDAndReaderAreBounded(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("fd-secret\n"); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	input, err := OpenTokenInput(Options{Command: CommandInstall, TokenFD: int(reader.Fd())})
	if err != nil {
		t.Fatalf("fd token: %v", err)
	}
	if input.Token() != "fd-secret" {
		t.Fatalf("fd token = %q", input.Token())
	}
	if err := input.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFromReader(strings.NewReader(strings.Repeat("x", maxTokenBytes+1))); err == nil {
		t.Fatal("accepted oversized token")
	}
	if _, err := ReadTokenFromReader(strings.NewReader("has whitespace")); err == nil {
		t.Fatal("accepted whitespace token")
	}
}

func TestSignedManifestAndArtifactDigests(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "antinat-agent-linux-amd64")
	contents := []byte("trusted artifact")
	if err := os.WriteFile(artifactPath, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestRaw := []byte(`{"schema_version":"1","release":"test","artifacts":{"antinat-agent-linux-amd64":"` + sha256Hex(contents) + `"},"trust_root":"test-root","signature_algorithm":"ed25519"}`)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignManifest(manifestRaw, private)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifySignedManifest(manifestRaw, signature, map[string]ed25519.PublicKey{"test-root": public})
	if err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
	if err := VerifyArtifactSet(dir, manifest); err != nil {
		t.Fatalf("verify artifacts: %v", err)
	}
	if _, err := VerifySignedManifest(append([]byte(nil), manifestRaw...), append(signature[:len(signature)-1], signature[len(signature)-1]^1), map[string]ed25519.PublicKey{"test-root": public}); err == nil {
		t.Fatal("accepted tampered signature")
	}
	if err := os.WriteFile(filepath.Join(dir, "link"), []byte("not used"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(artifactPath, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts["link"] = manifest.Artifacts["antinat-agent-linux-amd64"]
	if err := VerifyArtifactSet(dir, manifest); err == nil {
		t.Fatal("accepted symlink artifact")
	}
}

func TestOwnershipManifestPurgeAndFallback(t *testing.T) {
	root := t.TempDir()
	resource := filepath.Join(root, "bin", "agent")
	if err := os.MkdirAll(filepath.Dir(resource), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resource, []byte("owned"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "ownership.json")
	key := bytes.Repeat([]byte{0x42}, 32)
	manifest := OwnershipManifest{SchemaVersion: ownershipManifestSchema, InstallationID: "installation-1", Resources: []OwnedResource{{Root: root, Path: "bin/agent"}}}
	if err := CreateOwnershipManifest(manifestPath, manifest, key); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnershipManifest(manifestPath, key); err != nil {
		t.Fatalf("verify ownership: %v", err)
	}
	allowed := []OwnedResource{{Root: root, Path: "bin/agent"}}
	result, err := PurgeOwned(PurgeOptions{ManifestPath: manifestPath, HMACKey: key, Allowed: allowed})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if !result.ManifestVerified || !result.NoResidue || len(result.Removed) != 1 {
		t.Fatalf("purge result = %+v", result)
	}

	fallback := filepath.Join(root, "bin", "fallback")
	if err := os.WriteFile(fallback, []byte("owned"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = PurgeOwned(PurgeOptions{ManifestPath: manifestPath, HMACKey: key, Fallback: []OwnedResource{{Root: root, Path: "bin/fallback"}}})
	if err != nil {
		t.Fatalf("fallback purge: %v", err)
	}
	if !result.UsedFallback || !result.NoResidue {
		t.Fatalf("fallback result = %+v", result)
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeOwned(PurgeOptions{ManifestPath: filepath.Join(t.TempDir(), "missing"), Fallback: []OwnedResource{{Root: root, Path: "link"}}}); err == nil {
		t.Fatal("purge followed or removed symlink")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside resource was affected: %v", err)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(raw, []byte("\n{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnershipManifest(manifestPath, key); err == nil {
		t.Fatal("accepted ownership manifest with trailing JSON")
	}
}

func TestPurgeDirectoryPreflightsAllChildren(t *testing.T) {
	root := t.TempDir()
	ownedDir := filepath.Join(root, "backups")
	if err := os.MkdirAll(ownedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(ownedDir, "first")
	if err := os.WriteFile(first, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ownedDir, "z-link")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	result, err := PurgeOwned(PurgeOptions{
		ManifestPath: filepath.Join(t.TempDir(), "missing"),
		Fallback:     []OwnedResource{{Root: root, Path: "backups"}},
	})
	if err == nil || result.NoResidue {
		t.Fatal("purge accepted a directory containing a symlink")
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("preflight removed an earlier child: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(ownedDir, "z-link")); err != nil {
		t.Fatalf("preflight changed the symlink: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside resource was affected: %v", err)
	}
}

func TestVerifiedPurgeManifestMustMatchAllowlist(t *testing.T) {
	root := t.TempDir()
	owned := filepath.Join(root, "owned")
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(owned, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x19}, 32)
	manifestPath := filepath.Join(t.TempDir(), "ownership.json")
	manifest := OwnershipManifest{
		SchemaVersion:  ownershipManifestSchema,
		InstallationID: "installation-allowlist",
		Resources: []OwnedResource{
			{Root: root, Path: "owned"},
			{Root: root, Path: "outside"},
		},
	}
	if err := CreateOwnershipManifest(manifestPath, manifest, key); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeOwned(PurgeOptions{
		ManifestPath: manifestPath,
		HMACKey:      key,
		Allowed:      []OwnedResource{{Root: root, Path: "owned"}},
	}); err == nil {
		t.Fatal("purge accepted an authenticated resource outside the allowlist")
	}
	if _, err := os.Stat(owned); err != nil {
		t.Fatalf("allowlist rejection removed owned resource: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("allowlist rejection removed outside resource: %v", err)
	}
}

func TestDefaultPurgeResourcesIncludesControllerKeys(t *testing.T) {
	for _, layout := range []Layout{LinuxLayout(t.TempDir()), WindowsLayout(t.TempDir())} {
		found := false
		for _, resource := range DefaultPurgeResources(layout) {
			if resource.Root == layout.DataDir && resource.Path == "controller-keys" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("DefaultPurgeResources(%s) omitted controller-keys", layout.Platform)
		}
	}
}

func TestTransactionalUpgradeRestoresCompleteFileSet(t *testing.T) {
	root := t.TempDir()
	stage := t.TempDir()
	files := []string{"bin/agent", "var/controller.db", "var/state.db", "var/keys/node.key", "etc/agent.conf"}
	for _, path := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("old-"+path), 0o600); err != nil {
			t.Fatal(err)
		}
		staged := filepath.Join(stage, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(staged, []byte("new-"+path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var events []string
	result, err := TransactionalUpgrade(context.Background(), UpgradeRequest{
		LiveRoot: root, StagingRoot: stage, Files: files, CurrentVersion: 2, PreviousVersion: 1,
		Freeze:      func(context.Context) error { events = append(events, "freeze"); return nil },
		Unfreeze:    func(context.Context) error { events = append(events, "unfreeze"); return nil },
		Migrate:     func(context.Context, string) error { events = append(events, "migrate"); return nil },
		HealthCheck: func(context.Context, string) error { events = append(events, "health"); return errors.New("unhealthy") },
	})
	if err == nil || CodeOf(err) != ExitRollbackPerformed || !result.RolledBack {
		t.Fatalf("failed upgrade result=%+v err=%v code=%d", result, err, CodeOf(err))
	}
	if !reflect.DeepEqual(events, []string{"freeze", "migrate", "health", "unfreeze"}) {
		t.Fatalf("barrier events = %v", events)
	}
	for _, path := range files {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil || string(got) != "old-"+path {
			t.Fatalf("restored %s = %q err=%v", path, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".antinat-upgrade.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("upgrade lock residue: %v", err)
	}
	if result.RollbackJournalPath == "" {
		t.Fatal("successful rollback did not expose its journal path")
	}
	journalRaw, err := os.ReadFile(result.RollbackJournalPath)
	if err != nil {
		t.Fatalf("read rollback journal: %v", err)
	}
	var journal rollbackJournal
	if err := json.Unmarshal(journalRaw, &journal); err != nil {
		t.Fatalf("decode rollback journal: %v", err)
	}
	if journal.State != "complete" || len(journal.Completed) != len(files) {
		t.Fatalf("rollback journal = %+v", journal)
	}

	if err := ValidateNMinusOne(4, 2); err == nil || CodeOf(err) != ExitUpgradeMigrationBlocked {
		t.Fatal("accepted skipped schema upgrade")
	}
}

func TestTransactionalUpgradeReportsRollbackFailure(t *testing.T) {
	root := t.TempDir()
	stage := t.TempDir()
	files := []string{"first", "second"}
	for _, path := range files {
		if err := os.WriteFile(filepath.Join(root, path), []byte("old-"+path), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, path), []byte("new-"+path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := TransactionalUpgrade(context.Background(), UpgradeRequest{
		LiveRoot: root, StagingRoot: stage, Files: files, CurrentVersion: 2, PreviousVersion: 1,
		HealthCheck: func(context.Context, string) error {
			second := filepath.Join(root, "second")
			if err := os.Remove(second); err != nil {
				return fmt.Errorf("prepare rollback failure: %w", err)
			}
			if err := os.Mkdir(second, 0o700); err != nil {
				return fmt.Errorf("prepare rollback failure: %w", err)
			}
			return errors.New("unhealthy")
		},
	})
	if err == nil || CodeOf(err) != ExitGenericFailure {
		t.Fatalf("rollback failure result=%+v err=%v code=%d", result, err, CodeOf(err))
	}
	if !result.RollbackFailed || result.RolledBack {
		t.Fatalf("rollback status = %+v", result)
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("rollback failure was not explicit: %v", err)
	}
	journalRaw, err := os.ReadFile(result.RollbackJournalPath)
	if err != nil {
		t.Fatalf("read failed rollback journal: %v", err)
	}
	var journal rollbackJournal
	if err := json.Unmarshal(journalRaw, &journal); err != nil {
		t.Fatalf("decode failed rollback journal: %v", err)
	}
	if journal.State != "failed" {
		t.Fatalf("failed rollback journal = %+v", journal)
	}
}

func TestRestoreSnapshotVerifiesCompleteLiveSet(t *testing.T) {
	root := t.TempDir()
	backup := filepath.Join(t.TempDir(), "backup")
	files := []string{"first", "second"}
	for _, path := range files {
		if err := os.WriteFile(filepath.Join(root, path), []byte("old-"+path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := CreateSnapshot(root, backup, files)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	for _, path := range files {
		if err := os.WriteFile(filepath.Join(root, path), []byte("new-"+path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := restoreSnapshotWithProgress(root, backup, manifest, func(path string) error {
		if path == "first" {
			return os.WriteFile(filepath.Join(root, path), []byte("tampered"), 0o600)
		}
		return nil
	}); err == nil || !strings.Contains(err.Error(), "verify complete live restoration") {
		t.Fatalf("accepted a tampered live restore: %v", err)
	}
}

func TestTransactionalUpgradeAllowsMissingUnfreeze(t *testing.T) {
	root := t.TempDir()
	stage := t.TempDir()
	live := filepath.Join(root, "agent")
	staged := filepath.Join(stage, "agent")
	if err := os.WriteFile(live, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TransactionalUpgrade(context.Background(), UpgradeRequest{
		LiveRoot: root, StagingRoot: stage, Files: []string{"agent"},
		CurrentVersion: 2, PreviousVersion: 1,
		Freeze: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("upgrade with no unfreeze callback: %v", err)
	}
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
