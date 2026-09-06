// P14 repair-1 L2/L3 internal store tests: cleanup-tombstone duplicate refusal
// and corrupted-JSON fail-closed reads. Internal package so the tests can open a
// second raw connection (dsnFor) to corrupt the tombstone JSON directly.
package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestCleanupTombstoneCorruptedJSONFailsClosed (repair-1 L3): corrupted
// allowed_key_hashes / credential_versions JSON must produce an ERROR, never a
// silently-empty tombstone (which would falsely admit an old key).
func TestCleanupTombstoneCorruptedJSONFailsClosed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateNode(hereNode("node-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNodeCleanupTombstone(NodeCleanupTombstone{
		NodeID: "node-1", OperationID: "tomb-corrupt", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dsnFor(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE node_cleanup_tombstones SET allowed_key_hashes = '{not-json' WHERE node_id = 'node-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeCleanupTombstone("node-1"); err == nil {
		t.Fatal("corrupted allowed_key_hashes JSON decoded silently (fail-open)")
	}
	if _, err := s.ListCleanupTombstones(); err == nil {
		t.Fatal("corrupted allowed_key_hashes JSON decoded silently by ListCleanupTombstones")
	}
	// Credential-versions corruption fails closed the same way.
	if _, err := raw.Exec(`UPDATE node_cleanup_tombstones SET allowed_key_hashes = '["ok"]', credential_versions = '[oops' WHERE node_id = 'node-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeCleanupTombstone("node-1"); err == nil {
		t.Fatal("corrupted credential_versions JSON decoded silently (fail-open)")
	}
}

func hereNode(id string) Node {
	return Node{ID: id, Name: id}
}
