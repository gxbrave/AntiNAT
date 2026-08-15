package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// RED 6c: a migration that fails mid-way rolls back completely — the old
// schema stays intact, no partial table exists, no migration row is recorded,
// and the database remains fully openable. The error names the migration.
func TestMigrationFailureRollsBackLeavingOldDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	v0, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v0 != 5 {
		t.Fatalf("precondition: schema version = %d, want 5", v0)
	}

	// Second CREATE of the same table forces a failure mid-migration.
	badSQL := `CREATE TABLE broken_table (id INTEGER PRIMARY KEY);
	           CREATE TABLE broken_table (id INTEGER PRIMARY KEY);`
	err = s.applyMigration(6, "9999_broken.sql", badSQL)
	if err == nil {
		t.Fatal("applyMigration of broken SQL succeeded")
	}
	if !strings.Contains(err.Error(), "9999_broken.sql") {
		t.Fatalf("error does not name the failed migration: %v", err)
	}

	// Old DB intact: schema version unchanged, no partial table, no row.
	v1, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion after failure: %v", err)
	}
	if v1 != v0 {
		t.Fatalf("schema version changed after failed migration: %d -> %d", v0, v1)
	}
	var n int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE name = 'broken_table'",
	).Scan(&n); err != nil {
		t.Fatalf("sqlite_master query: %v", err)
	}
	if n != 0 {
		t.Fatal("partial table survived the failed migration")
	}
	var applied int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version = 6",
	).Scan(&applied); err != nil {
		t.Fatalf("schema_migrations query: %v", err)
	}
	if applied != 0 {
		t.Fatal("failed migration recorded as applied")
	}

	// The database is still fully usable after a restart.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen after failed migration: %v", err)
	}
	defer s2.Close()
	if v, err := s2.SchemaVersion(); err != nil || v != v0 {
		t.Fatalf("reopened schema version = %d (err %v), want %d", v, err, v0)
	}
}
