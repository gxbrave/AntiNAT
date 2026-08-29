package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
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

// A protected prefix must not pin the cleanup cursor forever. The reclaimable
// row intentionally sits after more than one bounded scan page, so repeated
// sweeps must make monotonic progress rather than selecting the same protected
// prefix on every call.
func TestR16Q2ControlInboxCleanupMakesFairProgressPastProtectedPrefix(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 30_000)
	const protectedCount = 1_024
	reclaimableID := "r16q2-reclaimable-message"
	recordProcessedInboxForQuality(t, s, ControlInboxItem{
		MessageID:       reclaimableID,
		NodeID:          "r16q2-node",
		MessageType:     "message_receipt",
		OperationID:     "r16q2-reclaimable-op",
		SemanticPayload: `{}`,
	})
	for i := 0; i < protectedCount; i++ {
		opID := fmt.Sprintf("r16q2-protected-op-%04d", i)
		if err := s.EnqueueControlOutbox(ControlOutboxItem{
			OperationID: opID, MessageType: "desired", NodeID: "r16q2-node", SemanticPayload: `{}`,
		}); err != nil {
			t.Fatalf("enqueue protected outbox %d: %v", i, err)
		}
		recordProcessedInboxForQuality(t, s, ControlInboxItem{
			MessageID:       fmt.Sprintf("r16q2-protected-message-%04d", i),
			NodeID:          "r16q2-node",
			MessageType:     "message_receipt",
			OperationID:     opID,
			SemanticPayload: `{}`,
		})
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}

	for pass := 0; pass < protectedCount+64; pass++ {
		if _, err := s.DeleteControlInboxBeforeLimit(30_000, 1); err != nil {
			t.Fatalf("cleanup pass %d: %v", pass, err)
		}
		remaining, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox WHERE message_id = ?`, reclaimableID)
		if err != nil {
			t.Fatal(err)
		}
		if remaining == 0 {
			return
		}
	}
	t.Fatalf("reclaimable inbox row remained behind %d protected rows after bounded passes", protectedCount)
}

// If the delete limit is reached before the raw scan page is exhausted, the
// cursor must stop at the last row actually examined. Advancing to the end of
// the page would skip rows until the high-water cycle resets.
func TestR16Q2CleanupCursorStopsAtDeletionBoundary(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 30_000)
	const protectedCount = 8
	var newestProtectedOp string
	for i := 0; i < protectedCount; i++ {
		opID := fmt.Sprintf("r16q2-boundary-op-%d", i)
		newestProtectedOp = opID
		if err := s.EnqueueControlOutbox(ControlOutboxItem{
			OperationID: opID, MessageType: "desired", NodeID: "r16q2-node", SemanticPayload: `{}`,
		}); err != nil {
			t.Fatal(err)
		}
		recordProcessedInboxForQuality(t, s, ControlInboxItem{
			MessageID: fmt.Sprintf("r16q2-boundary-message-%d", i),
			NodeID:    "r16q2-node", MessageType: "message_receipt",
			OperationID: opID, SemanticPayload: `{}`,
		})
	}
	// Insert the reclaimable row last so it is the first row in the descending
	// raw scan. The next three protected rows still fit in the raw scan page;
	// the row immediately below the deletion boundary must be visited next.
	reclaimableID := "r16q2-boundary-reclaimable"
	recordProcessedInboxForQuality(t, s, ControlInboxItem{
		MessageID: reclaimableID, NodeID: "r16q2-node", MessageType: "message_receipt",
		OperationID: "r16q2-boundary-reclaimable-op", SemanticPayload: `{}`,
	})
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.DeleteControlInboxBeforeLimit(30_000, 1); err != nil || removed != 1 {
		t.Fatalf("boundary cleanup removed %d rows (err %v), want 1", removed, err)
	}
	if _, err := s.db.Exec(`DELETE FROM control_outbox WHERE operation_id = ?`, newestProtectedOp); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.DeleteControlInboxBeforeLimit(30_000, 1); err != nil || removed != 1 {
		t.Fatalf("cleanup after boundary removed %d rows (err %v), want 1", removed, err)
	}
}

func TestR16Q2CleanupCursorRollbackDoesNotAdvance(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 30_000)
	messageID := "r16q2-rollback-cursor"
	recordProcessedInboxForQuality(t, s, ControlInboxItem{
		MessageID: messageID, NodeID: "r16q2-node", MessageType: "message_receipt",
		OperationID: "r16q2-rollback-op", SemanticPayload: `{}`,
	})
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1 WHERE message_id = ?`, messageID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER r16q2_abort_cleanup BEFORE DELETE ON control_inbox
		BEGIN SELECT RAISE(ABORT, 'r16q2 cleanup abort'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteControlInboxBeforeLimit(30_000, 1); err == nil {
		t.Fatal("cleanup succeeded while delete trigger aborted the transaction")
	}
	if s.inboxCleanupCursor.initialized {
		t.Fatal("cleanup cursor advanced after rolled-back transaction")
	}
	if _, err := s.db.Exec(`DROP TRIGGER r16q2_abort_cleanup`); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.DeleteControlInboxBeforeLimit(30_000, 1); err != nil || removed != 1 {
		t.Fatalf("cleanup after rollback removed %d rows (err %v), want 1", removed, err)
	}
}

func TestR16Q2CleanupCursorResetsOnCloseAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor-reopen.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	withStoreNow(t, 30_000)
	for i := 0; i < 6; i++ {
		recordProcessedInboxForQuality(t, s, ControlInboxItem{
			MessageID: fmt.Sprintf("r16q2-reopen-%d", i), NodeID: "r16q2-node",
			MessageType: "message_receipt", OperationID: fmt.Sprintf("r16q2-reopen-op-%d", i),
			SemanticPayload: `{}`,
		})
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteControlInboxBeforeLimit(30_000, 1); err != nil {
		t.Fatal(err)
	}
	if !s.inboxCleanupCursor.initialized {
		t.Fatal("cleanup cursor did not initialize during a partial pass")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.inboxCleanupCursor.closed || s.inboxCleanupCursor.initialized || s.inboxCleanupCursor.beforeID != 0 {
		t.Fatalf("closed cleanup cursor was not reset: closed=%t initialized=%t beforeID=%d", s.inboxCleanupCursor.closed, s.inboxCleanupCursor.initialized, s.inboxCleanupCursor.beforeID)
	}
	if _, err := s.DeleteControlInboxBeforeLimit(30_000, 1); !errors.Is(err, errStoreClosed) {
		t.Fatalf("cleanup after Close = %v, want errStoreClosed", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.inboxCleanupCursor.closed || reopened.inboxCleanupCursor.initialized || reopened.inboxCleanupCursor.beforeID != 0 {
		t.Fatalf("reopened Store inherited cleanup cursor state: closed=%t initialized=%t beforeID=%d", reopened.inboxCleanupCursor.closed, reopened.inboxCleanupCursor.initialized, reopened.inboxCleanupCursor.beforeID)
	}
}

func TestR16Q2NackedInboxTombstoneIsReclaimable(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 30_000)
	messageID := "r16q2-nacked-reclaimable"
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: messageID, NodeID: "r16q2-node", MessageType: "probe_result",
		OperationID: "r16q2-nacked-operation", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetControlInboxState(messageID, "NACKED"); err != nil {
		t.Fatalf("nack inbox row: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1 WHERE message_id = ?`, messageID); err != nil {
		t.Fatal(err)
	}
	removed, err := s.DeleteControlInboxBeforeLimit(30_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("nacked tombstone cleanup removed %d rows, want 1", removed)
	}
}

func TestR16Q2RejectedInboxTombstoneIsReclaimable(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 30_000)
	messageID := "r16q2-rejected-reclaimable"
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: messageID, NodeID: "r16q2-node", MessageType: "probe_ingress_receipt",
		SemanticPayload: "not-an-rct1-frame",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RejectControlInbox(messageID); err != nil {
		t.Fatalf("reject inbox row: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1 WHERE message_id = ?`, messageID); err != nil {
		t.Fatal(err)
	}
	removed, err := s.DeleteControlInboxBeforeLimit(30_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("rejected tombstone cleanup removed %d rows, want 1", removed)
	}
}

// The control-inbox cleanup keyset must not sort the complete historical
// inbox table. Its INTEGER PRIMARY KEY cursor is the monotonic work boundary.
func TestR16Q2ControlInboxCleanupAvoidsHistoricalSort(t *testing.T) {
	s := openTestStore(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN
		SELECT id, message_id, node_id, message_type,
		       COALESCE(operation_id, ''), semantic_payload, state, updated_at
		  FROM control_inbox NOT INDEXED
		 WHERE id <= ? AND id > 0
		 ORDER BY id DESC LIMIT ?`, 10_000, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notUsed, detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	planText := strings.ToUpper(plan.String())
	if strings.Contains(planText, "TEMP B-TREE") {
		t.Fatalf("control-inbox keyset uses a historical temp sort: %s", plan.String())
	}
	if !strings.Contains(planText, "INTEGER PRIMARY KEY") && !strings.Contains(planText, "ROWID") {
		t.Fatalf("control-inbox keyset is not rowid/index aligned: %s", plan.String())
	}
}

func TestR16Q2ProbeReceiptLookupUsesLiveExpiryIndex(t *testing.T) {
	s := openTestStore(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN
		SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status,
		       endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		  FROM probe_operations INDEXED BY idx_probe_live_expiry
		 WHERE node_id = ? AND status IN ('PENDING','ARMED','IN_FLIGHT')
		 ORDER BY expires_at, id LIMIT ?`, "r16q2-node", 256)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notUsed, detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(plan.String())
	if strings.Contains(upper, "TEMP B-TREE") {
		t.Fatalf("probe receipt lookup uses a historical temp sort: %s", plan.String())
	}
	if !strings.Contains(upper, "IDX_PROBE_LIVE_EXPIRY") {
		t.Fatalf("probe receipt lookup did not use the live-expiry index: %s", plan.String())
	}
}

func TestR16Q2CompatibilityProbeLookupExcludesExpiredNonterminal(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 100)
	const nodeID = "r16q2-compat-expired-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-compat-expired-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})
	arm := qualityLookupProbeArm(0x41)
	createQualityLookupOperation(t, s, "r16q2-compat-expired-row", nodeID, arm, "", 99)
	if _, err := s.ProbeOperationByArmDigest(arm.Digest()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("compatibility live lookup returned %v for expired nonterminal row, want ErrNotFound", err)
	}
}

func TestR16Q2UnknownProbeLookupReportsBudgetExhaustion(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "r16q2-lookup-node")
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: "r16q2-lookup-node", Name: "lookup", Protocol: "tcp"})
	if _, err := s.CreateProbeProvider(ProbeProvider{ID: "r16q2-provider", Name: "lookup-provider", PublicKey: "key", EgressIP: "198.51.100.9", Endpoint: "https://provider.invalid", Enabled: true, IndependentVantage: true}); err != nil {
		t.Fatal(err)
	}
	var target protocol.ProbeArm
	const operationCount = maxProbeLookupPages*defaultProbeLookupLimit + 1
	for i := 0; i < operationCount; i++ {
		var arm protocol.ProbeArm
		if _, err := rand.Read(arm.ProbeID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(arm.ProviderID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(arm.ProviderPublicKey[:]); err != nil {
			t.Fatal(err)
		}
		copy(arm.Activation[:], "r16q2-activation")
		arm.Endpoint = "198.51.100.7:8080"
		arm.TTLMS = 30_000
		if _, err := rand.Read(arm.ExpiryOpaque[:]); err != nil {
			t.Fatal(err)
		}
		if i == operationCount-1 {
			target = arm
		}
		if _, err := s.CreateProbeOperation(ProbeOperation{
			ID:           fmt.Sprintf("r16q2-lookup-op-%04d", i),
			NodeID:       "r16q2-lookup-node",
			ForwardID:    "r16q2-lookup-forward",
			ActivationID: "r16q2-activation",
			ProviderID:   "r16q2-provider",
			Status:       "PENDING",
			ArmHex:       hex.EncodeToString(arm.Canonical()),
			Endpoint:     arm.Endpoint,
			TTLMS:        arm.TTLMS,
			ExpiresAt:    time.Now().Add(time.Duration(i+1) * time.Minute).Unix(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpired(target.Digest(), "r16q2-lookup-node"); !errors.Is(err, ErrProbeLookupBudget) {
		t.Fatalf("probe lookup beyond %d-row budget returned %v, want ErrProbeLookupBudget", operationCount-1, err)
	}
}

func TestR16Q2ProbeLookupRejectsDuplicateLiveArmDigest(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-duplicate-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})
	arm := qualityLookupProbeArm(7)
	createQualityLookupOperation(t, s, "r16q2-duplicate-a", nodeID, arm, "", 30_100)
	createQualityLookupOperation(t, s, "r16q2-duplicate-b", nodeID, arm, "", 30_101)
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(arm.Digest(), nodeID, 2); !errors.Is(err, ErrProbeAmbiguous) {
		t.Fatalf("duplicate live digest lookup returned %v, want ErrProbeAmbiguous", err)
	}
}

func TestR16Q2UnknownProbeLookupProvesAbsenceBeforeBudget(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpired([32]byte{1}, "missing-node"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty lookup returned %v, want ErrNotFound", err)
	}
}

func qualityLookupProbeArm(seed byte) protocol.ProbeArm {
	var arm protocol.ProbeArm
	arm.ProbeID[0] = seed
	arm.ProviderID[0] = seed + 0x10
	arm.ProviderPublicKey[0] = seed + 0x20
	arm.ExpectedSourceIP = [4]byte{198, 51, 100, 9}
	arm.Activation[0] = seed + 0x30
	arm.Endpoint = "198.51.100.7:8080"
	arm.TTLMS = 30_000
	arm.ExpiryOpaque[0] = seed + 0x40
	return arm
}

func createQualityLookupOperation(t *testing.T, s *Store, id, nodeID string, arm protocol.ProbeArm, armHex string, expiresAt int64) {
	t.Helper()
	if err := arm.Validate(); err != nil {
		t.Fatalf("validate quality lookup arm: %v", err)
	}
	if armHex == "" {
		armHex = hex.EncodeToString(arm.Canonical())
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID:           id,
		NodeID:       nodeID,
		ForwardID:    "r16q2-lookup-forward",
		ActivationID: hex.EncodeToString(arm.Activation[:]),
		ProviderID:   hex.EncodeToString(arm.ProviderID[:]),
		Status:       "PENDING",
		Endpoint:     arm.Endpoint,
		ArmHex:       armHex,
		TTLMS:        arm.TTLMS,
		ExpiryOpaque: hex.EncodeToString(arm.ExpiryOpaque[:]),
		ExpiresAt:    expiresAt,
	}); err != nil {
		t.Fatalf("create quality lookup operation %q: %v", id, err)
	}
}

func TestR16Q2ProbeLookupExactBoundaryUnknownIsNotFound(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-exact-boundary-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})

	present := qualityLookupProbeArm(1)
	createQualityLookupOperation(t, s, "r16q2-exact-boundary-row", nodeID, present, "", 1)
	unknown := qualityLookupProbeArm(2).Digest()
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(unknown, nodeID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("one nonmatching row at limit boundary returned %v, want ErrNotFound", err)
	}
}

func TestR16Q2ProbeLookupCountsLookaheadDuplicateAsAmbiguous(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-duplicate-boundary-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})

	arm := qualityLookupProbeArm(3)
	createQualityLookupOperation(t, s, "r16q2-duplicate-boundary-in-budget", nodeID, arm, "", 1)
	createQualityLookupOperation(t, s, "r16q2-duplicate-boundary-lookahead", nodeID, arm, "", 2)
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(arm.Digest(), nodeID, 1); !errors.Is(err, ErrProbeAmbiguous) {
		t.Fatalf("in-budget match with lookahead duplicate returned %v, want ErrProbeAmbiguous", err)
	}
}

func TestR16Q2ProbeLookupDuplicateBeyondLookaheadIsBudget(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-duplicate-after-lookahead-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})
	arm := qualityLookupProbeArm(0x31)
	createQualityLookupOperation(t, s, "r16q2-duplicate-after-lookahead-match", nodeID, arm, "", 1)
	createQualityLookupOperation(t, s, "r16q2-duplicate-after-lookahead-filler", nodeID, qualityLookupProbeArm(0x32), "", 2)
	createQualityLookupOperation(t, s, "r16q2-duplicate-after-lookahead-duplicate", nodeID, arm, "", 3)
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(arm.Digest(), nodeID, 1); !errors.Is(err, ErrProbeLookupBudget) {
		t.Fatalf("match with duplicate beyond lookahead returned %v, want ErrProbeLookupBudget", err)
	}
}

func TestR16Q2ProbeLookupOverflowTargetBeyondSmallBoundIsBudget(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-overflow-node"

	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})

	createQualityLookupOperation(t, s, "r16q2-overflow-prefix", nodeID, qualityLookupProbeArm(1), "", 1)
	target := qualityLookupProbeArm(2)
	createQualityLookupOperation(t, s, "r16q2-overflow-target", nodeID, target, "", 2)
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(target.Digest(), nodeID, 1); !errors.Is(err, ErrProbeLookupBudget) {
		t.Fatalf("target beyond small lookup bound returned %v, want ErrProbeLookupBudget", err)
	}
}

func TestR16Q2ProbeLookupFindsTargetAfterUnrelatedCorruptArmWithinBound(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-corrupt-prefix-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})

	createQualityLookupOperation(t, s, "r16q2-corrupt-prefix", nodeID, qualityLookupProbeArm(1), "not-an-arm", 1)
	target := qualityLookupProbeArm(2)
	createQualityLookupOperation(t, s, "r16q2-corrupt-prefix-target", nodeID, target, "", 2)
	got, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(target.Digest(), nodeID, 2)
	if err != nil {
		t.Fatalf("valid target after unrelated corrupt row returned error: %v", err)
	}
	if got.ID != "r16q2-corrupt-prefix-target" {
		t.Fatalf("lookup returned operation %q, want valid target", got.ID)
	}
}

func TestR16Q2ProbeLookupCorruptPrefixBeyondBoundReportsBudget(t *testing.T) {
	s := openTestStore(t)
	const nodeID = "r16q2-corrupt-overflow-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})

	createQualityLookupOperation(t, s, "r16q2-corrupt-overflow-prefix", nodeID, qualityLookupProbeArm(1), "not-an-arm", 1)
	target := qualityLookupProbeArm(2)
	createQualityLookupOperation(t, s, "r16q2-corrupt-overflow-target", nodeID, target, "", 2)
	if _, err := s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(target.Digest(), nodeID, 1); !errors.Is(err, ErrProbeLookupBudget) {
		t.Fatalf("valid target beyond corrupt prefix bound returned %v, want ErrProbeLookupBudget", err)
	}
}

func TestR16Q2InboxCleanupRetainsCorruptProbeReceiptAndReclaimsOrdinaryRow(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 30_000)
	const nodeID = "r16q2-corrupt-cleanup-node"
	mustCreateNode(t, s, nodeID)
	mustCreateForward(t, s, Forward{ID: "r16q2-lookup-forward", NodeID: nodeID, Name: "lookup", Protocol: "tcp"})

	createQualityLookupOperation(t, s, "r16q2-corrupt-live-arm", nodeID, qualityLookupProbeArm(1), "not-an-arm", 30_100)
	receiptID := "r16q2-corrupt-live-receipt"
	receiptPayload := "RCT1" + strings.Repeat("\x00", protocol.ProbeDigestLen)
	recordProcessedInboxForQuality(t, s, ControlInboxItem{
		MessageID:       receiptID,
		NodeID:          nodeID,
		MessageType:     "probe_ingress_receipt",
		OperationID:     "r16q2-corrupt-live-arm",
		SemanticPayload: receiptPayload,
	})
	ordinaryID := "r16q2-ordinary-receipt"
	recordProcessedInboxForQuality(t, s, ControlInboxItem{
		MessageID:       ordinaryID,
		NodeID:          nodeID,
		MessageType:     "message_receipt",
		OperationID:     "r16q2-ordinary-operation",
		SemanticPayload: `{}`,
	})
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}

	removed, err := s.DeleteControlInboxBeforeLimit(30_000, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("cleanup removed %d inbox rows, want unrelated ordinary row only", removed)
	}
	if got, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox WHERE message_id = ?`, receiptID); err != nil || got != 1 {
		t.Fatalf("corrupt-dependent receipt count = %d (err %v), want 1", got, err)
	}
	if got, err := countRows(t, s, `SELECT COUNT(*) FROM control_inbox WHERE message_id = ?`, ordinaryID); err != nil || got != 0 {
		t.Fatalf("unrelated ordinary receipt count = %d (err %v), want 0", got, err)
	}
}
