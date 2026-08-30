package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/migrations"
	_ "modernc.org/sqlite"
)

// openR14LegacyV5 builds the last canonical pre-R14 schema without running the
// out-of-ledger compatibility helper. It is the upgrade fixture for an
// existing deployment whose schema_migrations tip is 0005.
func openR14LegacyV5(t *testing.T, path string) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", dsnFor(path))
	if err != nil {
		t.Fatalf("open legacy sqlite: %v", err)
	}
	st := &Store{db: db, path: path}
	if _, err := db.Exec(schemaMigrationsDDL); err != nil {
		db.Close()
		t.Fatalf("create schema_migrations: %v", err)
	}
	for version, name := range migrations.Names[:5] {
		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			db.Close()
			t.Fatalf("read legacy migration %s: %v", name, err)
		}
		if err := st.applyMigration(version+1, name, string(sqlBytes)); err != nil {
			db.Close()
			t.Fatalf("apply legacy migration %s: %v", name, err)
		}
	}
	return st
}

func TestR14FreshStoreRecordsHardeningMigration(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	version, err := st.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != 7 {
		t.Fatalf("SchemaVersion = %d, want 7 (0006_r13_hardening + 0007_traversal)", version)
	}
	var name string
	if err := st.db.QueryRow(`SELECT name FROM schema_migrations WHERE version = 6`).Scan(&name); err != nil {
		t.Fatalf("read migration 0006 ledger row: %v", err)
	}
	if name != "0006_r13_hardening.sql" {
		t.Fatalf("migration 6 name = %q", name)
	}
	for _, object := range []string{"probe_terminal_deliveries", "idx_control_outbox_command_message", "idx_control_outbox_operation_complete_message", "idx_control_outbox_controller_operation_complete_message", "idx_probe_terminal_delivery_state", "idx_probe_terminal_delivery"} {
		var count int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, object).Scan(&count); err != nil {
			t.Fatalf("check migration object %s: %v", object, err)
		}
		if count != 1 {
			t.Fatalf("migration object %s count = %d, want 1", object, count)
		}
	}
}

func TestR14UpgradeBackfillsLegacyOutboxCorrelationIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	legacy := openR14LegacyV5(t, path)
	if _, err := legacy.db.Exec(`INSERT INTO control_outbox
		(operation_id, message_type, node_id, semantic_payload, state, attempt_count, created_at, updated_at)
		VALUES ('legacy-op', 'desired', 'legacy-node', '{}', 'PENDING', 0, 10, 10)`); err != nil {
		legacy.Close()
		t.Fatalf("insert legacy outbox row: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy store: %v", err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade legacy store: %v", err)
	}
	defer upgraded.Close()
	version, err := upgraded.SchemaVersion()
	if err != nil || version != 7 {
		t.Fatalf("upgraded schema version = %d (err %v), want 7", version, err)
	}
	var commandID, resultID, controllerResultID string
	if err := upgraded.db.QueryRow(`SELECT command_message_id, operation_complete_message_id, controller_operation_complete_message_id
		FROM control_outbox WHERE operation_id = 'legacy-op' AND message_type = 'desired'`).Scan(&commandID, &resultID, &controllerResultID); err != nil {
		t.Fatalf("read backfilled correlation ids: %v", err)
	}
	if commandID != deterministicMessageID("legacy-op", "desired") ||
		resultID != deterministicMessageID(commandID, "operation_complete") ||
		controllerResultID != deterministicMessageID("legacy-op", "operation_complete") {
		t.Fatalf("backfilled correlation ids = %q, %q, %q", commandID, resultID, controllerResultID)
	}
}

func TestR14HardeningMigrationIsIdempotentAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer st.Close()
	var count int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 6 AND name = '0006_r13_hardening.sql'`).Scan(&count); err != nil {
		t.Fatalf("count migration 0006 rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("migration 0006 ledger rows = %d, want 1", count)
	}
}

func TestR14HardeningMigrationRollbackLeavesV5DatabaseIntact(t *testing.T) {
	st := openR14LegacyV5(t, filepath.Join(t.TempDir(), "controller.db"))
	defer st.Close()
	if err := st.applyMigration(6, "0006_r13_hardening.sql", `CREATE TABLE r14_partial (id INTEGER PRIMARY KEY);
CREATE TABLE r14_partial (id INTEGER PRIMARY KEY);`); err == nil {
		t.Fatal("broken hardening migration succeeded")
	}
	version, err := st.SchemaVersion()
	if err != nil || version != 5 {
		t.Fatalf("schema version after rollback = %d (err %v), want 5", version, err)
	}
	var count int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'r14_partial'`).Scan(&count); err != nil {
		t.Fatalf("check rolled-back table: %v", err)
	}
	if count != 0 {
		t.Fatal("partial hardening migration table survived rollback")
	}
}
