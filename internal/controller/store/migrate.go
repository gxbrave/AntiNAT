package store

import (
	"fmt"
	"os"

	"github.com/gxbrave/AntiNAT/migrations"
)

// schemaMigrationsDDL is the migration bookkeeping table (part of the frozen
// v0.8 §9.1 table set). It is created by the runner before any migration file
// is applied, so a partially applied database is still identifiable.
const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at INTEGER NOT NULL
) STRICT`

// migrate applies every pending owned migration in order, each inside its own
// transaction. Applying the same database twice is a no-op. A failing
// migration rolls back and surfaces an actionable error naming the file, so
// the database remains on its previous schema version.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaMigrationsDDL); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	for i, name := range migrations.Names {
		version := i + 1
		applied, err := s.migrationApplied(version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", name, err)
		}
		if err := s.applyMigration(version, name, string(sqlBytes)); err != nil {
			return fmt.Errorf("store: migration %s failed: %w", name, err)
		}
	}
	return nil
}

func (s *Store) migrationApplied(version int) (bool, error) {
	var count int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("store: query schema_migrations: %w", err)
	}
	return count > 0, nil
}

// applyMigration runs one migration file and records it atomically.
func (s *Store) applyMigration(version int, name, sqlText string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec(sqlText); err != nil {
		tx.Rollback()
		return fmt.Errorf("apply %s: %w", name, err)
	}
	if _, err := tx.Exec(
		"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
		version, name, now(),
	); err != nil {
		tx.Rollback()
		return fmt.Errorf("record %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", name, err)
	}
	return nil
}

// SchemaVersion returns the highest applied migration version (0 before any
// migration has run).
func (s *Store) SchemaVersion() (int, error) {
	var version int
	if err := s.db.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
	).Scan(&version); err != nil {
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	return version, nil
}

func mkdirAll(dir string) error {
	return os.MkdirAll(dir, 0o700)
}
