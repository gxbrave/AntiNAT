package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// BackupManifestSchema is the manifest format version (frozen state-model §6).
const BackupManifestSchema = "antinat.backup/v1"

// BackupFile is one hashed file inside a backup (frozen §7.4: per-file hash
// and permissions).
type BackupFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// BackupManifest describes a consistent backup: controller instance id,
// schema version, per-file hashes/permissions, creation time and the P14
// anti-rollback high-water + current key id set.
type BackupManifest struct {
	Schema               string       `json:"schema"`
	ControllerInstanceID string       `json:"controller_instance_id"`
	SchemaVersion        int          `json:"schema_version"`
	CreatedAt            int64        `json:"created_at"`
	Files                []BackupFile `json:"files"`
	// HighWater carries the desired/deletion/tombstone + node-revision
	// high-water values at backup time (P14 §7.4). Older backups without them
	// decode with zero values and are refused for restore (fail closed).
	HighWater BackupHighWater `json:"high_water,omitempty"`
	// KeyIDs lists the controller signing key ids present at backup time;
	// restore refuses a backup whose key set differs from the live keys.
	KeyIDs []string `json:"key_ids,omitempty"`
}

const backupDBName = "controller.db"
const backupManifestName = "manifest.json"

// BackupTo writes a consistent VACUUM INTO snapshot plus a hash/manifest into
// destDir (validated P03 backup path; never a bare copy of the WAL file). The
// file and its parent directory are fsynced before the manifest is recorded.
func (s *Store) BackupTo(destDir string) (BackupManifest, error) {
	return s.BackupToWithKeys(destDir, nil)
}

// BackupToWithKeys writes a VACUUM INTO snapshot with the P14 high-water and
// key-id set recorded in the manifest. keyIDs are the controller signing key
// ids at backup time; restore fails closed on a mismatch.
func (s *Store) BackupToWithKeys(destDir string, keyIDs []string) (BackupManifest, error) {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return BackupManifest{}, fmt.Errorf("store: backup mkdir: %w", err)
	}
	instanceID, err := s.InstanceID()
	if err != nil {
		return BackupManifest{}, err
	}
	schemaVersion, err := s.SchemaVersion()
	if err != nil {
		return BackupManifest{}, err
	}
	highWater, err := s.CurrentBackupHighWater()
	if err != nil {
		return BackupManifest{}, err
	}

	dbFile := filepath.Join(destDir, backupDBName)
	if _, err := s.db.Exec("VACUUM INTO ?", dbFile); err != nil {
		return BackupManifest{}, fmt.Errorf("store: vacuum into backup: %w", err)
	}
	if err := syncFileAndParent(dbFile); err != nil {
		return BackupManifest{}, err
	}

	sum, mode, err := hashAndMode(dbFile)
	if err != nil {
		return BackupManifest{}, err
	}
	manifest := BackupManifest{
		Schema:               BackupManifestSchema,
		ControllerInstanceID: instanceID,
		SchemaVersion:        schemaVersion,
		CreatedAt:            now(),
		Files: []BackupFile{
			{Name: backupDBName, SHA256: sum, Mode: mode},
		},
		HighWater: highWater,
		KeyIDs:    append([]string(nil), keyIDs...),
	}
	if err := writeManifest(destDir, manifest); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

// OpenBackup verifies a backup directory (manifest hashes, permissions,
// SQLite quick_check and foreign_key_check) and opens the snapshot as a
// store for restore verification. It fails closed on any mismatch.
func OpenBackup(dir string) (*Store, BackupManifest, error) {
	manifest, err := readManifest(dir)
	if err != nil {
		return nil, BackupManifest{}, err
	}
	for _, f := range manifest.Files {
		path := filepath.Join(dir, f.Name)
		got, mode, err := hashAndMode(path)
		if err != nil {
			return nil, BackupManifest{}, fmt.Errorf("store: backup verify %s: %w", f.Name, err)
		}
		if got != f.SHA256 {
			return nil, BackupManifest{}, fmt.Errorf("store: backup hash mismatch for %s", f.Name)
		}
		if mode != f.Mode {
			return nil, BackupManifest{}, fmt.Errorf("store: backup permission mismatch for %s", f.Name)
		}
	}

	s, err := Open(filepath.Join(dir, backupDBName))
	if err != nil {
		return nil, BackupManifest{}, fmt.Errorf("store: open backup: %w", err)
	}
	if err := s.ForeignKeyCheck(); err != nil {
		s.Close()
		return nil, BackupManifest{}, err
	}
	return s, manifest, nil
}

// ForeignKeyCheck runs PRAGMA foreign_key_check and fails closed on any
// violation.
func (s *Store) ForeignKeyCheck() error {
	rows, err := s.db.Query("PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("store: foreign key check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var table, parent string
		var rowid int64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err == nil {
			return fmt.Errorf("store: foreign key violation in %s (parent %s)", table, parent)
		}
		return errors.New("store: foreign key violation")
	}
	return rows.Err()
}

func readManifest(dir string) (BackupManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, backupManifestName))
	if err != nil {
		return BackupManifest{}, fmt.Errorf("store: read backup manifest: %w", err)
	}
	var m BackupManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return BackupManifest{}, fmt.Errorf("store: parse backup manifest: %w", err)
	}
	if m.Schema != BackupManifestSchema {
		return BackupManifest{}, fmt.Errorf("store: unsupported backup manifest schema %q", m.Schema)
	}
	return m, nil
}

func writeManifest(dir string, m BackupManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode backup manifest: %w", err)
	}
	path := filepath.Join(dir, backupManifestName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("store: write backup manifest: %w", err)
	}
	return syncFileAndParent(path)
}

func hashAndMode(path string) (string, uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, fmt.Errorf("store: read %s: %w", path, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", 0, fmt.Errorf("store: stat %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), uint32(st.Mode().Perm()), nil
}

func syncFileAndParent(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open for sync: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("store: sync file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close synced file: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("store: open parent dir: %w", err)
	}
	if err := dir.Sync(); err != nil {
		dir.Close()
		return fmt.Errorf("store: sync parent dir: %w", err)
	}
	return dir.Close()
}

// randomHex returns n random bytes as hex.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// openRawDB opens a second connection pool to the same database with the
// frozen pragmas (used by internal tests for lock contention).
func openRawDB(path string) (*sql.DB, error) {
	return sql.Open("sqlite", dsnFor(path))
}
