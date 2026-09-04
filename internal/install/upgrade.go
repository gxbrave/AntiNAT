package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const upgradeManifestSchema = "antinat.upgrade/v1"
const rollbackJournalSchema = "antinat.rollback/v1"

// SnapshotFile is one file in a transactional upgrade snapshot. Present=false
// records an optional file that did not exist before promotion, allowing a
// rollback to remove it without guessing about ownership.
type SnapshotFile struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
	Present bool   `json:"present"`
}

type SnapshotManifest struct {
	SchemaVersion string         `json:"schema"`
	CreatedAt     int64          `json:"created_at"`
	Files         []SnapshotFile `json:"files"`
}

// CreateSnapshot takes a consistent, caller-quiesced file snapshot. The
// caller is responsible for freezing the application before invoking it;
// TransactionalUpgrade provides that barrier for the common path.
func CreateSnapshot(root, destination string, files []string) (SnapshotManifest, error) {
	if root == "" || destination == "" {
		return SnapshotManifest{}, errors.New("snapshot root and destination are required")
	}
	if len(files) == 0 {
		return SnapshotManifest{}, errors.New("snapshot file set is empty")
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return SnapshotManifest{}, fmt.Errorf("create snapshot directory: %w", err)
	}
	files = uniqueSortedPaths(files)
	manifest := SnapshotManifest{SchemaVersion: upgradeManifestSchema, CreatedAt: time.Now().Unix(), Files: make([]SnapshotFile, 0, len(files))}
	for _, relative := range files {
		if err := validateRelativeResource(relative); err != nil {
			return SnapshotManifest{}, err
		}
		source, err := secureJoin(root, relative)
		if err != nil {
			return SnapshotManifest{}, err
		}
		info, err := os.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			manifest.Files = append(manifest.Files, SnapshotFile{Path: relative})
			continue
		}
		if err != nil {
			return SnapshotManifest{}, fmt.Errorf("stat snapshot file %q: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return SnapshotManifest{}, fmt.Errorf("snapshot file %q is not a regular non-symlink", relative)
		}
		if info.Size() > maxArtifactBytes {
			return SnapshotManifest{}, fmt.Errorf("snapshot file %q exceeds size limit", relative)
		}
		destinationPath, err := secureJoin(destination, relative)
		if err != nil {
			return SnapshotManifest{}, err
		}
		if err := copyFileAtomic(source, destinationPath, info.Mode().Perm()); err != nil {
			return SnapshotManifest{}, fmt.Errorf("snapshot file %q: %w", relative, err)
		}
		digest, err := fileSHA256(destinationPath)
		if err != nil {
			return SnapshotManifest{}, err
		}
		manifest.Files = append(manifest.Files, SnapshotFile{Path: relative, SHA256: digest, Mode: uint32(info.Mode().Perm()), Present: true})
	}
	if err := writeSnapshotManifest(destination, manifest); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

// VerifySnapshot validates every manifest entry and rejects a changed or
// symlinked backup before any restore begins.
func VerifySnapshot(destination string, manifest SnapshotManifest) error {
	return verifySnapshotFiles(destination, manifest, "snapshot")
}

func verifyLiveSnapshot(root string, manifest SnapshotManifest) error {
	return verifySnapshotFiles(root, manifest, "live")
}

func verifySnapshotFiles(root string, manifest SnapshotManifest, label string) error {
	if manifest.SchemaVersion != upgradeManifestSchema || len(manifest.Files) == 0 {
		return errors.New("invalid upgrade snapshot manifest")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, entry := range manifest.Files {
		if err := validateRelativeResource(entry.Path); err != nil {
			return err
		}
		if _, ok := seen[entry.Path]; ok {
			return fmt.Errorf("duplicate snapshot path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		path, err := secureJoin(root, entry.Path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if !entry.Present {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("absent %s path %q exists", label, entry.Path)
		}
		if err != nil {
			return fmt.Errorf("%s entry %q: %w", label, entry.Path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s entry %q is not a regular non-symlink", label, entry.Path)
		}
		if uint32(info.Mode().Perm()) != entry.Mode {
			return fmt.Errorf("%s mode mismatch for %q", label, entry.Path)
		}
		digest, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if digest != entry.SHA256 {
			return fmt.Errorf("%s digest mismatch for %q", label, entry.Path)
		}
	}
	return nil
}

// RestoreSnapshot restores the exact file set recorded by a verified snapshot.
// It refuses to replace symlinks and never follows a path outside root.
func RestoreSnapshot(root, destination string, manifest SnapshotManifest) error {
	return restoreSnapshotWithProgress(root, destination, manifest, nil)
}

func restoreSnapshotWithProgress(root, destination string, manifest SnapshotManifest, progress func(string) error) error {
	if err := VerifySnapshot(destination, manifest); err != nil {
		return err
	}
	if err := preflightRestoreTargets(root, manifest); err != nil {
		if verifyErr := verifyLiveSnapshot(root, manifest); verifyErr != nil {
			return errors.Join(err, fmt.Errorf("verify complete live restoration: %w", verifyErr))
		}
		return err
	}
	var restoreErrors []error
	for _, entry := range manifest.Files {
		target, err := secureJoin(root, entry.Path)
		if err != nil {
			restoreErrors = append(restoreErrors, err)
			continue
		}
		if !entry.Present {
			if err := removeRegularFile(target); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("remove promoted file %q: %w", entry.Path, err))
				continue
			}
		} else {
			source, err := secureJoin(destination, entry.Path)
			if err != nil {
				restoreErrors = append(restoreErrors, err)
				continue
			}
			if err := copyFileAtomic(source, target, os.FileMode(entry.Mode)); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("restore file %q: %w", entry.Path, err))
				continue
			}
		}
		if progress != nil {
			if err := progress(entry.Path); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("record restored file %q: %w", entry.Path, err))
			}
		}
	}
	if len(restoreErrors) != 0 {
		if err := verifyLiveSnapshot(root, manifest); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("verify complete live restoration: %w", err))
		}
		return errors.Join(restoreErrors...)
	}
	if err := verifyLiveSnapshot(root, manifest); err != nil {
		return fmt.Errorf("verify complete live restoration: %w", err)
	}
	return nil
}

func preflightRestoreTargets(root string, manifest SnapshotManifest) error {
	for _, entry := range manifest.Files {
		target, err := secureJoin(root, entry.Path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect restore target %q: %w", entry.Path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("restore target %q is not a regular non-symlink", entry.Path)
		}
	}
	return nil
}

// UpgradeRequest describes an application-quiesced, file-atomic upgrade. The
// file set must include every mutable state component that can affect startup:
// SQLite, bbolt, keys, config and binaries.
type UpgradeRequest struct {
	LiveRoot    string
	StagingRoot string
	BackupRoot  string
	Files       []string

	CurrentVersion  uint64
	PreviousVersion uint64

	Freeze      func(context.Context) error
	Unfreeze    func(context.Context) error
	Migrate     func(context.Context, string) error
	HealthCheck func(context.Context, string) error
}

type UpgradeResult struct {
	BackupPath          string
	RolledBack          bool
	RollbackFailed      bool
	RollbackJournalPath string
	Promoted            bool
	Manifest            SnapshotManifest
}

type rollbackJournal struct {
	SchemaVersion string           `json:"schema"`
	LiveRoot      string           `json:"live_root"`
	BackupPath    string           `json:"backup_path"`
	Manifest      SnapshotManifest `json:"manifest"`
	State         string           `json:"state"`
	Completed     []string         `json:"completed,omitempty"`
	Error         string           `json:"error,omitempty"`
}

var upgradeSequence atomic.Uint64

// TransactionalUpgrade snapshots the old complete file set, atomically
// promotes the staged set, runs migration and health gates, and restores the
// snapshot on every post-promotion failure. The service barrier is always
// released on return.
func TransactionalUpgrade(ctx context.Context, request UpgradeRequest) (result UpgradeResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.LiveRoot == "" || request.StagingRoot == "" {
		return result, upgradeError(ExitGenericFailure, "upgrade", errors.New("live and staging roots are required"))
	}
	if err := ValidateNMinusOne(request.CurrentVersion, request.PreviousVersion); err != nil {
		return result, err
	}
	if len(request.Files) == 0 {
		return result, upgradeError(ExitGenericFailure, "upgrade", errors.New("upgrade file set is empty"))
	}
	request.Files = uniqueSortedPaths(request.Files)
	if err := validateUpgradePaths(request); err != nil {
		return result, err
	}
	lock, err := acquireUpgradeLock(request.LiveRoot)
	if err != nil {
		return result, upgradeError(ExitPathOrServiceConflict, "upgrade", err)
	}
	defer releaseUpgradeLock(lock)

	if request.Freeze != nil {
		if err := request.Freeze(ctx); err != nil {
			return result, upgradeError(ExitGenericFailure, "freeze upgrade", err)
		}
		defer func() {
			if request.Unfreeze != nil {
				if unfreezeErr := request.Unfreeze(ctx); err == nil && unfreezeErr != nil {
					err = upgradeError(ExitGenericFailure, "unfreeze upgrade", unfreezeErr)
				}
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		return result, upgradeError(ExitGenericFailure, "upgrade", err)
	}
	backupRoot := request.BackupRoot
	if backupRoot == "" {
		backupRoot = filepath.Join(filepath.Dir(request.LiveRoot), "antinat-backups")
	}
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return result, upgradeError(ExitGenericFailure, "create upgrade backup root", err)
	}
	id := fmt.Sprintf("upgrade-%d-%d", time.Now().UnixNano(), upgradeSequence.Add(1))
	backupPath := filepath.Join(backupRoot, id)
	manifest, err := CreateSnapshot(request.LiveRoot, backupPath, request.Files)
	if err != nil {
		return result, upgradeError(ExitGenericFailure, "snapshot upgrade", err)
	}
	result.BackupPath, result.Manifest = backupPath, manifest
	if err := VerifySnapshot(backupPath, manifest); err != nil {
		return result, upgradeError(ExitGenericFailure, "verify upgrade snapshot", err)
	}

	for _, relative := range request.Files {
		if err := ctx.Err(); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "upgrade cancelled", err))
		}
		source, err := secureJoin(request.StagingRoot, relative)
		if err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "stage path", err))
		}
		info, err := os.Lstat(source)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if err == nil {
				err = errors.New("staged file is not a regular non-symlink")
			}
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "stage artifact", fmt.Errorf("%s: %w", relative, err)))
		}
		if info.Size() > maxArtifactBytes {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "stage artifact", fmt.Errorf("%s: staged file exceeds size limit", relative)))
		}
		target, err := secureJoin(request.LiveRoot, relative)
		if err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "promotion path", err))
		}
		if err := copyFileAtomic(source, target, info.Mode().Perm()); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "promote artifact", err))
		}
	}
	result.Promoted = true
	if request.Migrate != nil {
		if err := request.Migrate(ctx, request.LiveRoot); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "migration failed; rollback performed", err))
		}
	}
	if request.HealthCheck != nil {
		if err := request.HealthCheck(ctx, request.LiveRoot); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "health check failed; rollback performed", err))
		}
	}
	return result, nil
}

func rollbackUpgrade(ctx context.Context, request UpgradeRequest, result UpgradeResult, cause error) (UpgradeResult, error) {
	result.RollbackJournalPath = filepath.Join(result.BackupPath, "rollback.json")
	journal := rollbackJournal{
		SchemaVersion: rollbackJournalSchema,
		LiveRoot:      request.LiveRoot,
		BackupPath:    result.BackupPath,
		Manifest:      result.Manifest,
		State:         "in_progress",
	}
	journalErr := writeRollbackJournal(result.RollbackJournalPath, journal)
	restoreErr := restoreSnapshotWithProgress(request.LiveRoot, result.BackupPath, result.Manifest, func(path string) error {
		journal.Completed = append(journal.Completed, path)
		if journalErr != nil {
			return journalErr
		}
		return writeRollbackJournal(result.RollbackJournalPath, journal)
	})
	if restoreErr != nil {
		result.RollbackFailed = true
		journal.State = "failed"
		journal.Error = restoreErr.Error()
		if err := writeRollbackJournal(result.RollbackJournalPath, journal); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("record rollback failure: %w", err))
		}
		if journalErr != nil {
			restoreErr = errors.Join(journalErr, restoreErr)
		}
		return result, upgradeError(ExitGenericFailure, "rollback failed", errors.Join(cause, restoreErr))
	}
	result.RolledBack = true
	journal.State = "complete"
	if journalErr == nil {
		if err := writeRollbackJournal(result.RollbackJournalPath, journal); err != nil {
			return result, upgradeError(ExitRollbackPerformed, "rollback performed; journal finalization failed", errors.Join(cause, err))
		}
	} else {
		return result, upgradeError(ExitRollbackPerformed, "rollback performed; journal unavailable", errors.Join(cause, journalErr))
	}
	return result, cause
}

func writeRollbackJournal(path string, journal rollbackJournal) error {
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePrivate(path, raw, 0o600)
}

func validateUpgradePaths(request UpgradeRequest) error {
	for _, relative := range request.Files {
		if err := validateRelativeResource(relative); err != nil {
			return upgradeError(ExitUsageError, "upgrade paths", err)
		}
	}
	return nil
}

func upgradeError(code ExitCode, op string, err error) error {
	return &InstallerError{Code: code, Op: op, Cause: err}
}

func acquireUpgradeLock(root string) (*os.File, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, ".antinat-upgrade.lock")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.WriteString("upgrade barrier\n"); err != nil {
		file.Close()
		os.Remove(path)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return nil, err
	}
	return file, nil
}

func releaseUpgradeLock(file *os.File) {
	if file == nil {
		return
	}
	path := file.Name()
	_ = file.Close()
	_ = os.Remove(path)
	_ = syncParent(path)
}

func writeSnapshotManifest(destination string, manifest SnapshotManifest) error {
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePrivate(filepath.Join(destination, "manifest.json"), raw, 0o600)
}

func copyFileAtomic(source, destination string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source is not a regular non-symlink file")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".antinat-copy-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	written, err := io.Copy(tmp, io.LimitReader(in, maxArtifactBytes+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if written > maxArtifactBytes {
		tmp.Close()
		return errors.New("source exceeds size limit")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	return syncParent(destination)
}

func removeRegularFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to remove non-regular or symlink path")
	}
	return os.Remove(path)
}

func fileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("hash path is not a regular non-symlink file")
	}
	if info.Size() > maxArtifactBytes {
		return "", errors.New("hash path exceeds size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxArtifactBytes {
		return "", errors.New("hash path exceeds size limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func uniqueSortedPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		seen[path] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

var _ = strings.TrimSpace
