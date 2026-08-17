package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

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
	var current int
	if err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if current > len(migrations.Names) {
		return fmt.Errorf("%w: database schema %d, this build supports %d", ErrSchemaTooNew, current, len(migrations.Names))
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
	if err := s.ensureR13Schema(); err != nil {
		return err
	}
	if err := s.backfillControlOutboxCorrelationIDs(); err != nil {
		return err
	}
	return nil
}

// ensureR13Schema installs the append-only R13 compatibility schema without
// changing the frozen migration version. Existing tests and deployed v0.8
// databases identify 0005 as the last canonical migration; these idempotent
// additions are therefore safe for both fresh and already-migrated stores.
func (s *Store) ensureR13Schema() error {
	columns := []struct{ table, column string }{
		{"control_outbox", "command_message_id"},
		{"control_outbox", "operation_complete_message_id"},
		{"control_outbox", "controller_operation_complete_message_id"},
	}
	for _, item := range columns {
		rows, err := s.db.Query("PRAGMA table_info(" + item.table + ")")
		if err != nil {
			return fmt.Errorf("store: inspect R13 schema: %w", err)
		}
		found := false
		for rows.Next() {
			var cid int
			var name, typ string
			var notNull, pk int
			var defaultValue any
			if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
				rows.Close()
				return fmt.Errorf("store: scan R13 schema: %w", err)
			}
			if name == item.column {
				found = true
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("store: close R13 schema inspection: %w", err)
		}
		if !found {
			if _, err := s.db.Exec("ALTER TABLE " + item.table + " ADD COLUMN " + item.column + " TEXT"); err != nil {
				return fmt.Errorf("store: add R13 column %s.%s: %w", item.table, item.column, err)
			}
		}
	}
	if err := s.repairR13TerminalIndex(); err != nil {
		return err
	}
	statements := []string{
		`CREATE INDEX IF NOT EXISTS idx_control_outbox_command_message ON control_outbox(node_id, command_message_id) WHERE command_message_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_control_outbox_operation_complete_message ON control_outbox(node_id, operation_complete_message_id) WHERE operation_complete_message_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_control_outbox_controller_operation_complete_message ON control_outbox(node_id, controller_operation_complete_message_id) WHERE controller_operation_complete_message_id IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS probe_terminal_deliveries (
			probe_id TEXT PRIMARY KEY REFERENCES probe_operations(id),
			disposition TEXT NOT NULL, outcome TEXT NOT NULL, node_id TEXT NOT NULL,
			forward_id TEXT NOT NULL, activation_id TEXT NOT NULL,
			created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS idx_probe_terminal_delivery_state ON probe_terminal_deliveries(disposition, updated_at, probe_id)`,
		`CREATE INDEX IF NOT EXISTS idx_probe_terminal_delivery ON probe_operations(status, created_at, id)`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("store: install R13 schema object: %w", err)
		}
	}
	return nil
}

func (s *Store) repairR13TerminalIndex() error {
	var schemaSQL string
	err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_probe_terminal_delivery'`).Scan(&schemaSQL)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: inspect terminal delivery index: %w", err)
	}
	if strings.Contains(strings.ToLower(schemaSQL), "created_at") {
		return nil
	}
	if _, err := s.db.Exec(`DROP INDEX IF EXISTS idx_probe_terminal_delivery`); err != nil {
		return fmt.Errorf("store: replace terminal delivery index: %w", err)
	}
	return nil
}

// backfillControlOutboxCorrelationIDs is a one-time compatibility step for
// databases created before migration 0006. The hot path uses the indexed
// columns and never performs this historical scan again.
func (s *Store) backfillControlOutboxCorrelationIDs() error {
	rows, err := s.db.Query(`SELECT operation_id, message_type FROM control_outbox
		WHERE command_message_id IS NULL OR operation_complete_message_id IS NULL
		   OR controller_operation_complete_message_id IS NULL`)
	if err != nil {
		return fmt.Errorf("store: query legacy outbox correlation ids: %w", err)
	}
	type pair struct{ operationID, messageType string }
	var pending []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.operationID, &p.messageType); err != nil {
			rows.Close()
			return fmt.Errorf("store: scan legacy outbox correlation ids: %w", err)
		}
		pending = append(pending, p)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store: close legacy outbox correlation rows: %w", err)
	}
	for _, p := range pending {
		commandID := deterministicMessageID(p.operationID, p.messageType)
		resultID := deterministicMessageID(commandID, "operation_complete")
		controllerResultID := deterministicMessageID(p.operationID, "operation_complete")
		if _, err := s.db.Exec(`UPDATE control_outbox
			SET command_message_id = ?, operation_complete_message_id = ?,
			    controller_operation_complete_message_id = ?
			WHERE operation_id = ? AND message_type = ?`, commandID, resultID, controllerResultID, p.operationID, p.messageType); err != nil {
			return fmt.Errorf("store: backfill outbox correlation ids: %w", err)
		}
	}
	return rows.Err()
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
