package store

import (
	"database/sql"
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
	if version == 6 {
		sqlText, err = prepareR13HardeningSQL(tx, sqlText)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("prepare %s: %w", name, err)
		}
	}
	if _, err := tx.Exec(sqlText); err != nil {
		tx.Rollback()
		return fmt.Errorf("apply %s: %w", name, err)
	}
	if version == 6 {
		if err := backfillControlOutboxCorrelationIDsTx(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("backfill %s: %w", name, err)
		}
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

// prepareR13HardeningSQL makes the append-only 0006 file safe for databases
// created by the rejected R13 candidate. That candidate installed the three
// outbox columns outside schema_migrations; SQLite has no portable
// ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so only those already-present
// ALTER statements are omitted before the canonical SQL runs. All other
// schema work remains in migrations/0006_r13_hardening.sql and is committed
// with its ledger row by applyMigration.
func prepareR13HardeningSQL(tx *sql.Tx, sqlText string) (string, error) {
	for _, column := range []string{
		"command_message_id",
		"operation_complete_message_id",
		"controller_operation_complete_message_id",
	} {
		exists, err := controlOutboxColumnExists(tx, column)
		if err != nil {
			return "", err
		}
		if exists {
			statement := "ALTER TABLE control_outbox ADD COLUMN " + column + " TEXT;"
			sqlText = strings.Replace(sqlText, statement, "", 1)
		}
	}
	probeRevisionExists, err := tableColumnExists(tx, "probe_operations", "expected_forward_revision")
	if err != nil {
		return "", err
	}
	if probeRevisionExists {
		sqlText = strings.Replace(sqlText, "ALTER TABLE probe_operations ADD COLUMN expected_forward_revision INTEGER NOT NULL DEFAULT 0;", "", 1)
	}
	return sqlText, nil
}

func controlOutboxColumnExists(tx *sql.Tx, column string) (bool, error) {
	return tableColumnExists(tx, "control_outbox", column)
}

func tableColumnExists(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, fmt.Errorf("inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, fmt.Errorf("scan %s schema: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("read %s schema: %w", table, err)
	}
	return false, nil
}

// backfillControlOutboxCorrelationIDsTx fills only missing correlation values
// while the 0006 migration transaction is open. Keeping the backfill inside
// the same transaction as the schema and ledger row prevents a crash from
// leaving a partially upgraded outbox.
func backfillControlOutboxCorrelationIDsTx(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT operation_id, message_type,
		command_message_id, operation_complete_message_id,
		controller_operation_complete_message_id
		FROM control_outbox
		WHERE command_message_id IS NULL OR command_message_id = ''
		   OR operation_complete_message_id IS NULL OR operation_complete_message_id = ''
		   OR controller_operation_complete_message_id IS NULL OR controller_operation_complete_message_id = ''`)
	if err != nil {
		return fmt.Errorf("query legacy outbox correlation ids: %w", err)
	}
	type pendingCorrelation struct {
		operationID, messageType                string
		commandID, resultID, controllerResultID sql.NullString
	}
	var pending []pendingCorrelation
	for rows.Next() {
		var item pendingCorrelation
		if err := rows.Scan(&item.operationID, &item.messageType, &item.commandID, &item.resultID, &item.controllerResultID); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy outbox correlation ids: %w", err)
		}
		pending = append(pending, item)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy outbox correlation rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read legacy outbox correlation rows: %w", err)
	}
	for _, item := range pending {
		commandID := item.commandID.String
		if !item.commandID.Valid || commandID == "" {
			commandID = deterministicMessageID(item.operationID, item.messageType)
		}
		resultID := item.resultID.String
		if !item.resultID.Valid || resultID == "" {
			resultID = deterministicMessageID(commandID, "operation_complete")
		}
		controllerResultID := item.controllerResultID.String
		if !item.controllerResultID.Valid || controllerResultID == "" {
			controllerResultID = deterministicMessageID(item.operationID, "operation_complete")
		}
		if _, err := tx.Exec(`UPDATE control_outbox
			SET command_message_id = ?, operation_complete_message_id = ?,
			    controller_operation_complete_message_id = ?
			WHERE operation_id = ? AND message_type = ?`, commandID, resultID, controllerResultID, item.operationID, item.messageType); err != nil {
			return fmt.Errorf("update outbox correlation ids: %w", err)
		}
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
