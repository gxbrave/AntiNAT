package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func withStoreNow(t *testing.T, unix int64) {
	t.Helper()
	previous := now
	now = func() int64 { return unix }
	t.Cleanup(func() { now = previous })
}

func createTerminalProbeForCleanup(t *testing.T, s *Store, id string, updatedAt int64) {
	t.Helper()
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: id, NodeID: "cleanup-node", ForwardID: "cleanup-forward", ActivationID: "cleanup-activation",
		ProviderID: "cleanup-provider", Status: "PENDING", Endpoint: "198.51.100.7:8080",
		ArmHex: "41524d31", TTLMS: 30_000, ExpiryOpaque: "00112233445566778899aabbccddeeff",
		ExpiresAt: updatedAt + 3_000,
	}); err != nil {
		t.Fatalf("create operation %s: %v", id, err)
	}
	if err := s.SetProbeOperationStatus(id, string(protocol.OutcomeRejected)); err != nil {
		t.Fatalf("terminalize operation %s: %v", id, err)
	}
	if _, err := s.db.Exec(`UPDATE probe_operations SET created_at = ?, updated_at = ? WHERE id = ?`, updatedAt, updatedAt, id); err != nil {
		t.Fatalf("age operation %s: %v", id, err)
	}
	if _, err := s.db.Exec(`INSERT INTO probe_results (probe_id, kind, payload_hex, created_at) VALUES (?, 'rct1', ?, ?)`, id, fmt.Sprintf("aa%02x", len(id)), updatedAt); err != nil {
		t.Fatalf("insert evidence %s: %v", id, err)
	}
}

// Cleanup must process a bounded number of tombstones per pass. A large
// historical backlog must not turn one controller sweep into an unbounded
// action lock hold.
func TestTerminalProbeCleanupIsBounded(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 2_000)
	if err := s.CreateNode(Node{ID: "cleanup-node", Name: "cleanup-node"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		createTerminalProbeForCleanup(t, s, fmt.Sprintf("cleanup-op-%d", i), 1)
	}

	removed, err := s.DeleteTerminalProbeOperationsBeforeLimit(2_000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed %d tombstones, want bounded batch of 2", removed)
	}
	remaining, err := countRows(t, s, `SELECT COUNT(*) FROM probe_operations`)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining tombstones = %d, want 2", remaining)
	}

	removed, err = s.DeleteTerminalProbeOperationsBeforeLimit(2_000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("second cleanup removed %d tombstones, want 2", removed)
	}
	remaining, err = countRows(t, s, `SELECT COUNT(*) FROM probe_operations`)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("remaining tombstones after second pass = %d, want 0", remaining)
	}
}

// Result cleanup must be governed by the terminal tombstone retention
// boundary, not by the artifact's age alone. An unacknowledged RCT1 attached
// to a recent terminal operation remains available for replay/reconciliation.
func TestProbeCleanupRetainsRecentTerminalReceipt(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 2_000)
	if err := s.CreateNode(Node{ID: "cleanup-node", Name: "cleanup-node"}); err != nil {
		t.Fatal(err)
	}
	createTerminalProbeForCleanup(t, s, "recent-terminal", 2_000)
	if _, err := s.db.Exec(`UPDATE probe_results SET created_at = 1 WHERE probe_id = ?`, "recent-terminal"); err != nil {
		t.Fatal(err)
	}

	removed, err := s.DeleteProbeResultsBeforeLimit(2_000, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("removed %d result rows from a recent tombstone, want 0", removed)
	}
	if got, err := countRows(t, s, `SELECT COUNT(*) FROM probe_results WHERE probe_id = 'recent-terminal'`); err != nil || got != 1 {
		t.Fatalf("recent terminal receipt rows = %d (err=%v), want 1", got, err)
	}
}

// A terminal tombstone is retained exactly at the cutoff and continues to
// reject late rewrites; only after the boundary passes can cleanup remove it.
func TestTerminalProbeRetentionBoundaryPreventsRevival(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 2_000)
	if err := s.CreateNode(Node{ID: "cleanup-node", Name: "cleanup-node"}); err != nil {
		t.Fatal(err)
	}
	createTerminalProbeForCleanup(t, s, "boundary-terminal", 2_000)
	if removed, err := s.DeleteTerminalProbeOperationsBeforeLimit(2_000, 1); err != nil {
		t.Fatal(err)
	} else if removed != 0 {
		t.Fatalf("boundary cleanup removed %d tombstones, want 0", removed)
	}
	if err := s.SetProbeOperationStatus("boundary-terminal", string(protocol.OutcomeTimeout)); !errors.Is(err, ErrProbeTerminal) {
		t.Fatalf("late rewrite at retention boundary = %v, want ErrProbeTerminal", err)
	}
	if _, err := s.db.Exec(`UPDATE probe_operations SET updated_at = 1 WHERE id = ?`, "boundary-terminal"); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.DeleteTerminalProbeOperationsBeforeLimit(2_000, 1); err != nil {
		t.Fatal(err)
	} else if removed != 1 {
		t.Fatalf("post-boundary cleanup removed %d tombstones, want 1", removed)
	}
	if err := s.SetProbeOperationStatus("boundary-terminal", string(protocol.OutcomeTimeout)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late rewrite after tombstone GC = %v, want ErrNotFound", err)
	}
}

// Expiry must use the caller's controlled timestamp and the exact boundary
// (expires_at <= now) rather than the process wall clock.
func TestProbeExpiryUsesControlledTimestampBoundary(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 1_000)
	if err := s.CreateNode(Node{ID: "cleanup-node", Name: "cleanup-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: "boundary-op", NodeID: "cleanup-node", ForwardID: "f", ActivationID: "a", ProviderID: "p",
		Status: "PENDING", Endpoint: "198.51.100.7:8080", ArmHex: "41524d31", TTLMS: 30_000,
		ExpiryOpaque: "00112233445566778899aabbccddeeff", ExpiresAt: 1_000,
	}); err != nil {
		t.Fatal(err)
	}
	expired, err := s.ExpireProbeOperationsLimit(1_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ID != "boundary-op" || expired[0].Status != string(protocol.OutcomeTimeout) {
		t.Fatalf("expired operations = %+v, want boundary-op TIMEOUT", expired)
	}
	got, err := s.GetProbeOperation("boundary-op")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != string(protocol.OutcomeTimeout) {
		t.Fatalf("status = %q, want TIMEOUT", got.Status)
	}
	if err := s.SetProbeOperationStatus("boundary-op", string(protocol.OutcomeRejected)); !errors.Is(err, ErrProbeTerminal) {
		t.Fatalf("late terminal rewrite = %v, want ErrProbeTerminal", err)
	}
}

func countRows(t *testing.T, s *Store, query string, args ...any) (int, error) {
	t.Helper()
	var count int
	err := s.db.QueryRow(query, args...).Scan(&count)
	return count, err
}
