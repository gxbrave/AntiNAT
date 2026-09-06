package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/migrations"
)

func TestR16MigrationRejectsLedgerGapAndWrongName(t *testing.T) {
	t.Run("gap", func(t *testing.T) {
		s := openR14LegacyV5(t, filepath.Join(t.TempDir(), "gap.db"))
		defer s.Close()
		if _, err := s.db.Exec(`DELETE FROM schema_migrations WHERE version = 3`); err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(); err == nil {
			t.Fatal("migration accepted a schema ledger gap")
		}
	})
	t.Run("wrong-name", func(t *testing.T) {
		s := openR14LegacyV5(t, filepath.Join(t.TempDir(), "wrong-name.db"))
		defer s.Close()
		if _, err := s.db.Exec(`UPDATE schema_migrations SET name = 'wrong.sql' WHERE version = 5`); err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(); err == nil {
			t.Fatal("migration accepted a mismatched schema ledger name")
		}
	})
}

func TestR16MigrationRejectsRecordedV6WithMissingObject(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(`DROP INDEX idx_control_outbox_command_message`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err == nil {
		t.Fatal("migration accepted recorded v6 with a missing required index")
	}
}

func TestR16MigrationRejectsRecordedV6WithWrongObjectKind(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(`DROP INDEX idx_control_outbox_command_message`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TABLE idx_control_outbox_command_message (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err == nil {
		t.Fatal("migration accepted a required index name backed by a table")
	}
}

func TestR16MigrationBackfillHardBudgetRollsBack(t *testing.T) {
	s := openR14LegacyV5(t, filepath.Join(t.TempDir(), "budget.db"))
	defer s.Close()
	oldBudget := migrationBackfillBudget
	migrationBackfillBudget = 2
	defer func() { migrationBackfillBudget = oldBudget }()
	for i := 0; i < 3; i++ {
		if _, err := s.db.Exec(`INSERT INTO control_outbox
			(operation_id, message_type, node_id, semantic_payload, state, attempt_count, created_at, updated_at)
			VALUES (?, 'desired', 'budget-node', '{}', 'PENDING', 0, 1, 1)`,
			strings.Repeat("b", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	sqlBytes, err := migrations.FS.ReadFile("0006_r13_hardening.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyMigration(6, "0006_r13_hardening.sql", string(sqlBytes)); err == nil {
		t.Fatal("migration exceeded the configured backfill budget")
	}
	version, err := s.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("schema version after budget rollback = %d, want 5", version)
	}
	var tableSQL string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'control_outbox'`).Scan(&tableSQL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tableSQL, "command_message_id") {
		t.Fatal("backfill budget failure left migration columns behind")
	}
}

func TestR16CleanupIndexesExposeOrderedKeys(t *testing.T) {
	s := openTestStore(t)
	for _, definition := range requiredR13Indexes {
		if err := validateR13IndexDefinition(s.db, definition); err != nil {
			t.Fatalf("index %s definition validation: %v", definition.name, err)
		}
	}
	for _, name := range []string{"idx_control_inbox_replay_gc", "idx_control_inbox_state_page", "idx_probe_terminal_expiry", "idx_probe_live_expiry", "idx_probe_terminal_created", "idx_probe_terminal_updated"} {
		var sqlText string
		err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&sqlText)
		if err != nil {
			t.Fatalf("read index %s: %v", name, err)
		}
		if !strings.Contains(sqlText, "id") {
			t.Fatalf("index %s lacks deterministic id key: %q", name, sqlText)
		}
	}
}
