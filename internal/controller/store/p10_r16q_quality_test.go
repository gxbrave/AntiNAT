package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/migrations"
)

func recordProcessedInboxForQuality(t *testing.T, s *Store, item ControlInboxItem) {
	t.Helper()
	if _, err := s.RecordControlInbox(item); err != nil {
		t.Fatal(err)
	}
	if err := s.SetControlInboxState(item.MessageID, "PROCESSED"); err != nil {
		t.Fatal(err)
	}
}

// Processed replay rows use an id high-water and a caller-sized batch. The
// cleanup must reclaim every ordinary result/receipt class, not just the probe
// result class, while leaving rows newer than the retention cutoff untouched.
func TestR16QControlInboxCleanupUsesBoundedHighWater(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 10_000)
	for i, messageType := range []string{"operation_complete", "message_receipt", "probe_result", "desired_result"} {
		recordProcessedInboxForQuality(t, s, ControlInboxItem{
			MessageID:       fmt.Sprintf("r16q-old-%d", i),
			NodeID:          "r16q-node",
			MessageType:     messageType,
			OperationID:     fmt.Sprintf("r16q-op-%d", i),
			SemanticPayload: fmt.Sprintf(`{"probe_id":"r16q-op-%d"}`, i),
		})
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER r16q_inbox_high_water AFTER DELETE ON control_inbox
		BEGIN
			INSERT OR IGNORE INTO control_inbox
			(message_id, node_id, message_type, semantic_payload, state, operation_id, created_at, updated_at)
			VALUES ('r16q-during', 'r16q-node', 'message_receipt', 'during', 'PROCESSED', 'during-op', 10_000, 10_000);
		END`); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(`DROP TRIGGER r16q_inbox_high_water`)

	removed, err := s.DeleteControlInboxBeforeLimit(10_000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("first inbox cleanup removed %d rows, want 2", removed)
	}
	remainingOld, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox WHERE updated_at < 10_000`)
	if err != nil {
		t.Fatal(err)
	}
	if remainingOld != 2 {
		t.Fatalf("old inbox high-water rows remaining = %d, want 2", remainingOld)
	}
	if got, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox WHERE message_id = 'r16q-during'`); err != nil || got != 1 {
		t.Fatalf("row inserted during cleanup count = %d (err %v), want 1", got, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER r16q_inbox_high_water`); err != nil {
		t.Fatal(err)
	}
	if removed, err = s.DeleteControlInboxBeforeLimit(10_000, 2); err != nil || removed != 2 {
		t.Fatalf("second inbox cleanup removed %d rows (err %v), want 2", removed, err)
	}
	if got, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox WHERE message_id = 'r16q-during'`); err != nil || got != 1 {
		t.Fatalf("row inserted during cleanup count after second pass = %d (err %v), want 1", got, err)
	}
}

// A processed tombstone remains until its durable result/receipt dependency is
// gone. Once the outbox/deletion/live-probe fences resolve, the same bounded
// cleanup may reclaim it.
func TestR16QControlInboxCleanupRetainsLiveResendDependencies(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 20_000)
	if err := s.CreateNode(Node{ID: "r16q-node", Name: "r16q-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "r16q-forward", NodeID: "r16q-node", Name: "r16q-forward", Protocol: "tcp", CurrentActivationID: "r16q-activation", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueControlOutbox(ControlOutboxItem{OperationID: "r16q-command", MessageType: "desired", NodeID: "r16q-node", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{ID: "r16q-delete", ForwardID: "r16q-forward", Status: "PENDING", DesiredRevision: 1}, ControlOutboxItem{OperationID: "r16q-delete", MessageType: "desired", NodeID: "r16q-node", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{ID: "r16q-probe", NodeID: "r16q-node", ForwardID: "r16q-forward", ActivationID: "r16q-activation", ProviderID: "r16q-provider", Status: "IN_FLIGHT", Endpoint: "198.51.100.7:8080", ArmHex: "41524d31", ExpiresAt: 20_030}); err != nil {
		t.Fatal(err)
	}

	recordProcessedInboxForQuality(t, s, ControlInboxItem{MessageID: "r16q-receipt", NodeID: "r16q-node", MessageType: "message_receipt", OperationID: deterministicMessageID("r16q-command", "desired"), SemanticPayload: `{"operation_id":"r16q-command"}`})
	recordProcessedInboxForQuality(t, s, ControlInboxItem{MessageID: deterministicMessageID("r16q-delete", "operation_complete"), NodeID: "r16q-node", MessageType: "operation_complete", OperationID: "r16q-delete", SemanticPayload: `{"deletion_operation_id":"r16q-delete"}`})
	recordProcessedInboxForQuality(t, s, ControlInboxItem{MessageID: "r16q-probe-result", NodeID: "r16q-node", MessageType: "probe_result", OperationID: "r16q-probe", SemanticPayload: `{"probe_id":"r16q-probe","outcome":"REJECTED"}`})
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}

	if removed, err := s.DeleteControlInboxBeforeLimit(20_000, 100); err != nil || removed != 0 {
		t.Fatalf("cleanup removed live dependency rows = %d (err %v), want 0", removed, err)
	}

	if _, err := s.db.Exec(`DELETE FROM control_outbox WHERE operation_id = 'r16q-command'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM control_outbox WHERE operation_id = 'r16q-delete'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE forward_deletion_operations SET status = 'COMPLETED' WHERE id = 'r16q-delete'`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProbeOperationStatus("r16q-probe", "REJECTED"); err != nil {
		t.Fatal(err)
	}
	removed, err := s.DeleteControlInboxBeforeLimit(20_000, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 {
		t.Fatalf("cleanup after dependency resolution removed %d rows, want 3", removed)
	}
}

// A same-named R13 index with incorrect columns/predicate must fail closed;
// CREATE INDEX IF NOT EXISTS cannot be treated as validation.
func TestR16QMigrationRejectsWrongSameNamedIndexDefinition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong-index.db")
	s := openR14LegacyV5(t, path)
	defer s.Close()
	if _, err := s.db.Exec(`CREATE INDEX idx_control_inbox_replay_gc
		ON control_inbox(state, id) WHERE state = 'PROCESSED'`); err != nil {
		t.Fatal(err)
	}
	sqlBytes, err := migrations.FS.ReadFile("0006_r13_hardening.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyMigration(6, "0006_r13_hardening.sql", string(sqlBytes)); err == nil {
		t.Fatal("migration accepted a wrong same-named index definition")
	}
	if version, err := s.SchemaVersion(); err != nil || version != 5 {
		t.Fatalf("failed migration changed schema version to %d (err %v), want 5", version, err)
	}
	if _, err := s.db.Exec(`DROP INDEX idx_control_inbox_replay_gc`); err != nil {
		t.Fatal(err)
	}
	if err := s.applyMigration(6, "0006_r13_hardening.sql", string(sqlBytes)); err != nil {
		t.Fatalf("corrected migration did not apply: %v", err)
	}
	if _, err := s.db.Exec(`SELECT 1 FROM sqlite_master WHERE name = 'idx_control_inbox_replay_gc'`); err != nil {
		t.Fatal(err)
	}
}

func TestR16QMigrationRejectsWrongIndexPredicateAfterLedger(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(`DROP INDEX idx_control_inbox_replay_gc`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE INDEX idx_control_inbox_replay_gc ON control_inbox(message_type, state, updated_at, id)`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err == nil {
		t.Fatal("migrate accepted a recorded index with a missing partial predicate")
	}
	if _, err := s.GetForward("missing"); !errors.Is(err, ErrForwardNotFound) {
		// Keep this test tied to the store package's real error plumbing; the
		// assertion also prevents accidentally replacing the DB with a fake.
		t.Fatalf("unexpected store probe after failed migration: %v", err)
	}
}
