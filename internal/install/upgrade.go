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
	BackupPath             string
	RolledBack             bool
	RollbackFailed         bool
	RollbackJournalPath    string
	TransactionJournalPath string
	Promoted               bool
	Manifest               SnapshotManifest
}

const upgradeTransactionJournalSchema = "antinat.upgrade-transaction/v1"

// upgradeTransactionJournal is written before the first live file is
// promoted. A process crash therefore leaves enough authenticated-by-location
// metadata to restore the complete pre-upgrade snapshot on the next run.
type upgradeTransactionJournal struct {
	SchemaVersion string           `json:"schema"`
	LiveRoot      string           `json:"live_root"`
	StagingRoot   string           `json:"staging_root"`
	BackupPath    string           `json:"backup_path"`
	Manifest      SnapshotManifest `json:"manifest"`
	State         string           `json:"state"`
	Promoted      []string         `json:"promoted,omitempty"`
	Restored      []string         `json:"restored,omitempty"`
	Error         string           `json:"error,omitempty"`
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
	if request.LiveRoot, err = canonicalUpgradePath(request.LiveRoot); err != nil {
		return result, upgradeError(ExitGenericFailure, "upgrade live root", err)
	}
	if request.StagingRoot, err = canonicalUpgradePath(request.StagingRoot); err != nil {
		return result, upgradeError(ExitGenericFailure, "upgrade staging root", err)
	}
	if request.BackupRoot != "" {
		if request.BackupRoot, err = canonicalUpgradePath(request.BackupRoot); err != nil {
			return result, upgradeError(ExitGenericFailure, "upgrade backup root", err)
		}
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
	if backupRoot, err = canonicalUpgradePath(backupRoot); err != nil {
		return result, upgradeError(ExitGenericFailure, "upgrade backup root", err)
	}
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return result, upgradeError(ExitGenericFailure, "create upgrade backup root", err)
	}
	if err := recoverInterruptedUpgrade(ctx, request.LiveRoot, backupRoot); err != nil {
		return result, upgradeError(ExitGenericFailure, "recover interrupted upgrade", err)
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
	result.TransactionJournalPath = filepath.Join(backupPath, "transaction.json")
	transaction := upgradeTransactionJournal{
		SchemaVersion: upgradeTransactionJournalSchema,
		LiveRoot:      request.LiveRoot,
		StagingRoot:   request.StagingRoot,
		BackupPath:    backupPath,
		Manifest:      manifest,
		State:         "snapshot_ready",
	}
	if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
		return result, upgradeError(ExitGenericFailure, "journal upgrade snapshot", err)
	}
	transaction.State = "promoting"
	if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
		return result, upgradeError(ExitGenericFailure, "journal upgrade promotion", err)
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
		transaction.Promoted = append(transaction.Promoted, relative)
		if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "journal promoted artifact", err))
		}
	}
	result.Promoted = true
	transaction.State = "promoted"
	if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
		return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "journal promoted upgrade", err))
	}
	if request.Migrate != nil {
		transaction.State = "migrating"
		if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "journal migration", err))
		}
		if err := request.Migrate(ctx, request.LiveRoot); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "migration failed; rollback performed", err))
		}
	}
	if request.HealthCheck != nil {
		transaction.State = "health_checking"
		if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "journal health check", err))
		}
		if err := request.HealthCheck(ctx, request.LiveRoot); err != nil {
			return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "health check failed; rollback performed", err))
		}
	}
	transaction.State = "complete"
	if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
		return rollbackUpgrade(ctx, request, result, upgradeError(ExitRollbackPerformed, "journal completed upgrade", err))
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
	transaction, transactionErr := readUpgradeTransactionJournal(result.TransactionJournalPath)
	if transactionErr == nil {
		transaction.State = "rollback_in_progress"
		transaction.Error = cause.Error()
		if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil && journalErr == nil {
			journalErr = err
		}
	}
	restoreErr := restoreSnapshotWithProgress(request.LiveRoot, result.BackupPath, result.Manifest, func(path string) error {
		journal.Completed = append(journal.Completed, path)
		if err := writeRollbackJournal(result.RollbackJournalPath, journal); err != nil {
			journalErr = err
			return err
		}
		journalErr = nil
		if transactionErr == nil {
			transaction.Restored = append(transaction.Restored, path)
			return writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction)
		}
		return nil
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
		if transactionErr == nil {
			transaction.State = "rollback_failed"
			transaction.Error = restoreErr.Error()
			if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
				restoreErr = errors.Join(restoreErr, err)
			}
		}
		return result, upgradeError(ExitGenericFailure, "rollback failed", errors.Join(cause, restoreErr))
	}
	result.RolledBack = true
	journal.State = "complete"
	if err := writeRollbackJournal(result.RollbackJournalPath, journal); err != nil {
		return result, upgradeError(ExitRollbackPerformed, "rollback performed; journal finalization failed", errors.Join(cause, err))
	}
	if transactionErr == nil {
		transaction.State = "rolled_back"
		if err := writeUpgradeTransactionJournal(result.TransactionJournalPath, transaction); err != nil {
			return result, upgradeError(ExitRollbackPerformed, "rollback performed; transaction journal finalization failed", errors.Join(cause, err))
		}
	} else if journalErr != nil {
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

func writeUpgradeTransactionJournal(path string, journal upgradeTransactionJournal) error {
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePrivate(path, raw, 0o600)
}

func readUpgradeTransactionJournal(path string) (upgradeTransactionJournal, error) {
	var journal upgradeTransactionJournal
	raw, err := readProtectedFile(path, 8<<20, "upgrade transaction journal")
	if err != nil {
		return journal, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&journal); err != nil {
		return journal, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return journal, errors.New("upgrade transaction journal has trailing JSON values")
		}
		return journal, err
	}
	return journal, nil
}

func canonicalUpgradePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("upgrade path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(abs)
	if clean != abs {
		return "", errors.New("upgrade path is not canonical")
	}
	return clean, nil
}

func validateUpgradeTransactionJournal(journal upgradeTransactionJournal, liveRoot, backupPath string) error {
	if journal.SchemaVersion != upgradeTransactionJournalSchema {
		return errors.New("unsupported upgrade transaction journal schema")
	}
	canonicalLive, err := filepath.Abs(liveRoot)
	if err != nil || filepath.Clean(canonicalLive) != canonicalLive || journal.LiveRoot != canonicalLive {
		return errors.New("upgrade transaction journal live root mismatch")
	}
	canonicalBackup, err := filepath.Abs(backupPath)
	if err != nil || filepath.Clean(canonicalBackup) != canonicalBackup || journal.BackupPath != canonicalBackup {
		return errors.New("upgrade transaction journal backup path mismatch")
	}
	switch journal.State {
	case "snapshot_ready", "promoting", "promoted", "migrating", "health_checking", "rollback_in_progress":
	default:
		return fmt.Errorf("upgrade transaction journal is not recoverable in state %q", journal.State)
	}
	return VerifySnapshot(canonicalBackup, journal.Manifest)
}

// RecoverInterruptedUpgrade restores every recoverable transaction for the
// supplied live root. It is safe to call after a process crash because the
// advisory lock is held by the caller and each journal is atomically written.
func RecoverInterruptedUpgrade(ctx context.Context, liveRoot, backupRoot string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if liveRoot == "" || backupRoot == "" {
		return errors.New("live and backup roots are required")
	}
	var err error
	if liveRoot, err = canonicalUpgradePath(liveRoot); err != nil {
		return err
	}
	if backupRoot, err = canonicalUpgradePath(backupRoot); err != nil {
		return err
	}
	lock, err := acquireUpgradeLock(liveRoot)
	if err != nil {
		return err
	}
	defer releaseUpgradeLock(lock)
	return recoverInterruptedUpgrade(ctx, liveRoot, backupRoot)
}

func recoverInterruptedUpgrade(ctx context.Context, liveRoot, backupRoot string) error {
	entries, err := os.ReadDir(backupRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		backupPath := filepath.Join(backupRoot, entry.Name())
		journalPath := filepath.Join(backupPath, "transaction.json")
		if _, err := os.Lstat(journalPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		journal, err := readUpgradeTransactionJournal(journalPath)
		if err != nil {
			return fmt.Errorf("read interrupted upgrade journal %q: %w", journalPath, err)
		}
		if journal.State == "complete" || journal.State == "rolled_back" || journal.State == "recovered" {
			continue
		}
		if err := validateUpgradeTransactionJournal(journal, liveRoot, backupPath); err != nil {
			return fmt.Errorf("validate interrupted upgrade journal %q: %w", journalPath, err)
		}
		if err := restoreSnapshotWithProgress(liveRoot, backupPath, journal.Manifest, nil); err != nil {
			journal.State = "rollback_failed"
			journal.Error = err.Error()
			_ = writeUpgradeTransactionJournal(journalPath, journal)
			return fmt.Errorf("restore interrupted upgrade %q: %w", backupPath, err)
		}
		journal.State = "recovered"
		journal.Error = "interrupted upgrade restored before retry"
		if err := writeUpgradeTransactionJournal(journalPath, journal); err != nil {
			return fmt.Errorf("finalize interrupted upgrade journal %q: %w", journalPath, err)
		}
	}
	return nil
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
