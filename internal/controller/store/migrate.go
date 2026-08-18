package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gxbrave/AntiNAT/migrations"
)

const migrationBackfillBatch = 256

// migrationBackfillBudget is deliberately finite: a very large legacy
// database must be upgraded offline rather than holding one writer transaction
// indefinitely. Tests may lower it to exercise rollback behavior.
var migrationBackfillBudget = 10_000

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
	if err := s.validateMigrationLedger(); err != nil {
		return err
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
		if version <= current {
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
	if err := s.validateMigrationLedger(); err != nil {
		return err
	}
	return s.validateAppliedSchema()
}

func (s *Store) validateMigrationLedger() error {
	rows, err := s.db.Query("SELECT version, name FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("store: read schema migration ledger: %w", err)
	}
	defer rows.Close()
	expected := 1
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return fmt.Errorf("store: scan schema migration ledger: %w", err)
		}
		if version > len(migrations.Names) {
			return fmt.Errorf("%w: migration ledger version %d is unsupported", ErrSchemaTooNew, version)
		}
		if version != expected {
			return fmt.Errorf("%w: migration ledger gap or duplicate at version %d (want %d)", ErrNotMigrated, version, expected)
		}
		if name != migrations.Names[version-1] {
			return fmt.Errorf("%w: migration %d is %q, want %q", ErrNotMigrated, version, name, migrations.Names[version-1])
		}
		expected++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: read schema migration ledger: %w", err)
	}
	return nil
}

func (s *Store) validateAppliedSchema() error {
	var version int
	if err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return fmt.Errorf("store: read applied schema version: %w", err)
	}
	if version >= 6 {
		if err := validateR13HardeningObjects(s.db); err != nil {
			return err
		}
	}
	return nil
}

type schemaQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func validateR13HardeningObjects(q schemaQueryer) error {
	for _, column := range []string{
		"command_message_id", "operation_complete_message_id",
		"controller_operation_complete_message_id",
	} {
		if ok, err := schemaColumnExists(q, "control_outbox", column); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("%w: migration 6 missing control_outbox.%s", ErrNotMigrated, column)
		}
	}
	if ok, err := schemaColumnExists(q, "probe_operations", "expected_forward_revision"); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: migration 6 missing probe_operations.expected_forward_revision", ErrNotMigrated)
	}
	objects := map[string]string{
		"probe_terminal_deliveries":                                "table",
		"idx_control_outbox_command_message":                       "index",
		"idx_control_outbox_operation_complete_message":            "index",
		"idx_control_outbox_controller_operation_complete_message": "index",
		"idx_probe_terminal_delivery_state":                        "index",
		"idx_probe_terminal_delivery":                              "index",
		"idx_control_inbox_replay_gc":                              "index",
		"idx_control_inbox_state_page":                             "index",
		"idx_probe_terminal_expiry":                                "index",
		"idx_probe_live_expiry":                                    "index",
		"idx_probe_terminal_created":                               "index",
		"idx_probe_terminal_updated":                               "index",
	}
	for object, wantType := range objects {
		var gotType sql.NullString
		if err := q.QueryRow("SELECT type FROM sqlite_master WHERE name = ?", object).Scan(&gotType); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: migration 6 missing required object %s", ErrNotMigrated, object)
		} else if err != nil {
			return fmt.Errorf("store: inspect migration object %s: %w", object, err)
		}
		if !gotType.Valid || gotType.String != wantType {
			return fmt.Errorf("%w: migration 6 object %s has type %q, want %q", ErrNotMigrated, object, gotType.String, wantType)
		}
	}
	return nil
}

func schemaColumnExists(q schemaQueryer, table, column string) (bool, error) {
	rows, err := q.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, fmt.Errorf("store: inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, fmt.Errorf("store: scan %s schema: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("store: read %s schema: %w", table, err)
	}
	return false, nil
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
		if err := validateR13HardeningObjects(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("validate %s: %w", name, err)
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
// while the 0006 migration transaction is open. It uses an id keyset and a
// hard total budget so a legacy backlog cannot create an unbounded upgrade
// transaction. Keeping the backfill inside the same transaction as the schema
// and ledger row makes an over-budget upgrade fully roll back.
func backfillControlOutboxCorrelationIDsTx(tx *sql.Tx) error {
	lastID := int64(0)
	processed := 0
	for {
		rows, err := tx.Query(`SELECT id, operation_id, message_type,
			command_message_id, operation_complete_message_id,
			controller_operation_complete_message_id
			FROM control_outbox
			WHERE id > ? AND (command_message_id IS NULL OR command_message_id = ''
			   OR operation_complete_message_id IS NULL OR operation_complete_message_id = ''
			   OR controller_operation_complete_message_id IS NULL OR controller_operation_complete_message_id = '')
			ORDER BY id LIMIT ?`, lastID, migrationBackfillBatch)
		if err != nil {
			return fmt.Errorf("query legacy outbox correlation ids: %w", err)
		}
		type pendingCorrelation struct {
			id                                      int64
			operationID, messageType                string
			commandID, resultID, controllerResultID sql.NullString
		}
		pending := make([]pendingCorrelation, 0, migrationBackfillBatch)
		for rows.Next() {
			var item pendingCorrelation
			if err := rows.Scan(&item.id, &item.operationID, &item.messageType,
				&item.commandID, &item.resultID, &item.controllerResultID); err != nil {
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
		if len(pending) == 0 {
			return nil
		}
		if processed+len(pending) > migrationBackfillBudget {
			return fmt.Errorf("legacy outbox correlation backfill exceeds hard budget %d; run offline migration", migrationBackfillBudget)
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
				WHERE id = ?`, commandID, resultID, controllerResultID, item.id); err != nil {
				return fmt.Errorf("update outbox correlation ids: %w", err)
			}
			lastID = item.id
			processed++
		}
	}
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
