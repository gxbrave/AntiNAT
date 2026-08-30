package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// openTestStore opens a store on a fresh temp database.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustCreateForward(t *testing.T, s *Store, f Forward) Forward {
	t.Helper()
	got, err := s.CreateForward(f)
	if err != nil {
		t.Fatalf("create forward %s: %v", f.ID, err)
	}
	return got
}

// TestProbeProviderCRUD covers registration, listing, and the enabled flag of
// the operator-owned probe provider registry (migration 0004).
func TestProbeProviderCRUD(t *testing.T) {
	s := openTestStore(t)

	p, err := s.CreateProbeProvider(ProbeProvider{
		ID:        "prov-1",
		Name:      "edge-1",
		PublicKey: "deadbeef",
		EgressIP:  "198.51.100.9",
		Endpoint:  "https://probe.example.com",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("create probe provider: %v", err)
	}
	if p.ID != "prov-1" || !p.Enabled {
		t.Fatalf("unexpected provider row: %+v", p)
	}

	got, err := s.GetProbeProvider("prov-1")
	if err != nil {
		t.Fatalf("get probe provider: %v", err)
	}
	if got.EgressIP != "198.51.100.9" || got.PublicKey != "deadbeef" {
		t.Fatalf("unexpected provider: %+v", got)
	}

	if err := s.SetProbeProviderEnabled("prov-1", false); err != nil {
		t.Fatalf("disable provider: %v", err)
	}
	got, _ = s.GetProbeProvider("prov-1")
	if got.Enabled {
		t.Fatalf("provider still enabled after disable")
	}

	if _, err := s.GetProbeProvider("missing"); err == nil {
		t.Fatalf("expected error for missing provider")
	}
}

// TestProbeOperationLifecycle covers the durable probe operation journal:
// PENDING -> ARMED -> result, with the frozen outcome registry values.
func TestProbeOperationLifecycle(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "n1")
	mustCreateForward(t, s, Forward{ID: "f1", NodeID: "n1", Name: "fwd1", Protocol: "tcp"})

	op, err := s.CreateProbeOperation(ProbeOperation{
		ID:           "probe-1",
		NodeID:       "n1",
		ForwardID:    "f1",
		ActivationID: "act-1",
		ProviderID:   "prov-1",
		Status:       "PENDING",
		Endpoint:     "198.51.100.7:8080",
		ArmHex:       "41524d31",
		TTLMS:        30000,
		ExpiryOpaque: "00112233445566778899aabbccddeeff",
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("create probe operation: %v", err)
	}
	if op.ID != "probe-1" || op.Status != "PENDING" {
		t.Fatalf("unexpected op: %+v", op)
	}

	got, err := s.GetProbeOperation("probe-1")
	if err != nil {
		t.Fatalf("get probe operation: %v", err)
	}
	if got.ArmHex != "41524d31" {
		t.Fatalf("arm hex not round-tripped: %q", got.ArmHex)
	}

	if err := s.SetProbeOperationStatus("probe-1", "ARMED"); err != nil {
		t.Fatalf("set status: %v", err)
	}
	got, _ = s.GetProbeOperation("probe-1")
	if got.Status != "ARMED" {
		t.Fatalf("status = %q, want ARMED", got.Status)
	}

	challengeHash := strings.Repeat("ca", protocol.ProbeDigestLen)
	if err := s.SetProbeOperationChallenge("probe-1", challengeHash); err != nil {
		t.Fatalf("set challenge: %v", err)
	}
	got, _ = s.GetProbeOperation("probe-1")
	if got.ChallengeHash != challengeHash {
		t.Fatalf("challenge hash not persisted")
	}
	if err := s.SetProbeOperationChallenge("probe-1", strings.Repeat("be", protocol.ProbeDigestLen)); !errors.Is(err, ErrProbeChallengeConflict) {
		t.Fatalf("contradictory challenge update = %v, want ErrProbeChallengeConflict", err)
	}
	got, _ = s.GetProbeOperation("probe-1")
	if got.ChallengeHash != challengeHash {
		t.Fatalf("contradictory challenge update overwrote evidence: %q", got.ChallengeHash)
	}

	// Result journaling.
	if err := s.RecordProbeResult("probe-1", "rct1", "aabbcc"); err != nil {
		t.Fatalf("record result: %v", err)
	}
	results, err := s.ListProbeResults("probe-1")
	if err != nil {
		t.Fatalf("list results: %v", err)
	}
	if len(results) != 1 || results[0].Kind != "rct1" || results[0].PayloadHex != "aabbcc" {
		t.Fatalf("unexpected results: %+v", results)
	}
	if _, err := s.db.Exec(`UPDATE probe_operations SET expires_at = 1 WHERE id = ?`, "probe-1"); err != nil {
		t.Fatalf("expire probe operation: %v", err)
	}
	if err := s.SetProbeOperationStatus("probe-1", string(protocol.OutcomeRejected)); !errors.Is(err, ErrProbeExpired) {
		t.Fatalf("expired probe transition = %v, want ErrProbeExpired", err)
	}
	if err := s.SetProbeOperationStatus("probe-1", string(protocol.OutcomeTimeout)); err != nil {
		t.Fatalf("expired probe timeout transition: %v", err)
	}

	// Unknown probe: result recording must fail (FK) and lookup must fail.
	if err := s.RecordProbeResult("missing", "rct1", "aa"); err == nil {
		t.Fatalf("expected FK failure for unknown probe")
	}
	if _, err := s.GetProbeOperation("missing"); err == nil {
		t.Fatalf("expected not found for missing probe")
	}
}

// TestForwardActivationCAS covers the orthogonal activation mirror: the
// frozen forward_runtime_status row accepts same-activation updates, rejects
// stale-activation events (ErrCASConflict), and lets the forward's CURRENT
// activation replace the mirror.
func TestForwardActivationCAS(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "n1")
	f := mustCreateForward(t, s, Forward{ID: "f1", NodeID: "n1", Name: "fwd1", Protocol: "tcp"})

	if err := s.EnsureForwardActivation(ForwardActivationRow{
		ID: "act-row-1", ForwardID: "f1", ActivationID: "act-1", SpecRevision: 1,
	}); err != nil {
		t.Fatalf("ensure activation: %v", err)
	}

	// Same-activation update succeeds on an absent mirror row.
	if err := s.SetForwardRuntimeStatus("f1", "act-1", f.Revision, legalRuntimeSnapshot("NOT_TESTED", "NOT_TESTED", "NONE")); err != nil {
		t.Fatalf("set runtime status: %v", err)
	}
	got, err := s.GetForwardRuntimeStatus("f1")
	if err != nil {
		t.Fatalf("get runtime status: %v", err)
	}
	if got.ActivationID != "act-1" {
		t.Fatalf("runtime status bound to %q, want act-1", got.ActivationID)
	}

	// Same-activation update succeeds (the mirror follows the current event).
	if err := s.SetForwardRuntimeStatus("f1", "act-1", f.Revision, legalRuntimeSnapshot("OPEN_FROM_VANTAGE", "VERIFIED", "PUBLISHED_VERIFIED")); err != nil {
		t.Fatalf("update runtime status: %v", err)
	}
	got2, _ := s.GetForwardRuntimeStatus("f1")
	if got2.SnapshotJSON != legalRuntimeSnapshot("OPEN_FROM_VANTAGE", "VERIFIED", "PUBLISHED_VERIFIED") {
		t.Fatalf("snapshot not advanced: %+v", got2)
	}

	// A stale activation event (neither the mirror's activation nor the
	// forward's current activation) must be rejected and leave the row
	// untouched.
	if err := s.SetForwardRuntimeStatus("f1", "act-stale", f.Revision, legalRuntimeSnapshot("REJECTED", "FAILED", "NONE")); err == nil {
		t.Fatalf("expected CAS conflict for stale activation event")
	}
	got3, _ := s.GetForwardRuntimeStatus("f1")
	if got3.ActivationID != "act-1" || got3.SnapshotJSON != legalRuntimeSnapshot("OPEN_FROM_VANTAGE", "VERIFIED", "PUBLISHED_VERIFIED") {
		t.Fatalf("stale event overwrote current state: %+v", got3)
	}

	// The forward's current activation (advance via CASForwardActivation)
	// replaces the mirror.
	if err := s.CASForwardActivation("f1", f.Revision, "act-2"); err != nil {
		t.Fatalf("CAS forward activation: %v", err)
	}
	if err := s.EnsureForwardActivation(ForwardActivationRow{
		ID: "act-row-2", ForwardID: "f1", ActivationID: "act-2", SpecRevision: 2,
	}); err != nil {
		t.Fatalf("ensure activation 2: %v", err)
	}
	if err := s.SetForwardRuntimeStatus("f1", "act-2", f.Revision+1, legalRuntimeSnapshot("NOT_TESTED", "NOT_TESTED", "NONE")); err != nil {
		t.Fatalf("set runtime status for current activation: %v", err)
	}
	got4, _ := s.GetForwardRuntimeStatus("f1")
	if got4.ActivationID != "act-2" {
		t.Fatalf("current activation did not replace mirror: %+v", got4)
	}

	// After the mirror moved to act-2, an act-1 event is stale and rejected.
	if err := s.SetForwardRuntimeStatus("f1", "act-1", f.Revision+1, legalRuntimeSnapshot("REJECTED", "FAILED", "NONE")); err == nil {
		t.Fatalf("expected CAS conflict for old activation after advance")
	}
}

func TestPublishProbeJoinRequiresCompleteEvidenceAndLegalSnapshot(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "n1")
	mustCreateForward(t, s, Forward{
		ID: "f-join", NodeID: "n1", Name: "join", Protocol: "tcp",
		CurrentActivationID: "act-1", Revision: 1,
	})
	if _, err := s.CreateProbeProvider(ProbeProvider{
		ID: "provider-1", Name: "independent", PublicKey: "00", EgressIP: "198.51.100.9",
		Endpoint: "https://provider.invalid", Enabled: true, IndependentVantage: true,
	}); err != nil {
		t.Fatalf("create join provider: %v", err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: "probe-join", NodeID: "n1", ForwardID: "f-join", ActivationID: "act-1",
		ProviderID: "provider-1", Status: "IN_FLIGHT", Endpoint: "198.51.100.7:8080",
		ArmHex: "41524d31", ChallengeHash: "abc", TTLMS: 30000, ExpiryOpaque: "00112233445566778899aabbccddeeff",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("create join operation: %v", err)
	}
	valid := `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"HEALTHY","wan_reachability_state":"OPEN_FROM_VANTAGE","return_path_state":"VERIFIED","target_health_state":"PASS","publication_state":"PUBLISHED_VERIFIED","data_plane_state":"READY"}`

	if err := s.PublishProbeJoin("probe-join", "PENDING", "f-join", "act-1", valid); err == nil {
		t.Fatal("PENDING operation published OPEN_FROM_VANTAGE")
	}
	if err := s.PublishProbeJoin("probe-join", "IN_FLIGHT", "f-join", "act-1", valid); err == nil {
		t.Fatal("join without provider/WAN1/ACK1/RCT1 evidence published")
	}

	for _, result := range []struct{ kind, payload string }{
		{kind: "provider", payload: `{"probe_id":"probe-join","accepted":true,"challenge_hash":"abc","wan1_frame":"wan1","ack1_frame":"ack1"}`},
		{kind: "wan1", payload: "wan1"},
		{kind: "ack1", payload: "ack1"},
		{kind: "rct1", payload: "rct1"},
	} {
		if err := s.RecordProbeResult("probe-join", result.kind, result.payload); err != nil {
			t.Fatalf("record %s: %v", result.kind, err)
		}
	}
	if err := s.RecordProbeResult("probe-join", "rct1", "duplicate"); err == nil {
		t.Fatal("duplicate RCT1 evidence was accepted")
	}
	unknownField := `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"HEALTHY","wan_reachability_state":"OPEN_FROM_VANTAGE","return_path_state":"VERIFIED","target_health_state":"PASS","publication_state":"PUBLISHED_VERIFIED","data_plane_state":"READY","unexpected":"reject"}`
	if err := s.PublishProbeJoin("probe-join", "IN_FLIGHT", "f-join", "act-1", unknownField); err == nil {
		t.Fatal("activation snapshot with an unknown field was published")
	}
	contradictory := `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"FIRST_HOP_MAPPED","keepalive_state":"HEALTHY","wan_reachability_state":"OPEN_FROM_VANTAGE","return_path_state":"VERIFIED","target_health_state":"PASS","publication_state":"PUBLISHED_VERIFIED","data_plane_state":"READY"}`
	if err := s.PublishProbeJoin("probe-join", "IN_FLIGHT", "f-join", "act-1", contradictory); err == nil {
		t.Fatal("contradictory activation snapshot was published")
	}
}

func TestTerminalProbeTombstoneGCPreventsRevival(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "n1")
	mustCreateForward(t, s, Forward{ID: "f1", NodeID: "n1", Name: "gc", Protocol: "tcp"})
	if _, err := s.CreateProbeProvider(ProbeProvider{ID: "provider-1", Name: "gc", PublicKey: "00", EgressIP: "198.51.100.9", Endpoint: "https://provider.invalid", Enabled: true, IndependentVantage: true}); err != nil {
		t.Fatalf("create gc provider: %v", err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: "probe-gc", NodeID: "n1", ForwardID: "f1", ActivationID: "act-1", ProviderID: "provider-1",
		Status: "PENDING", Endpoint: "198.51.100.7:8080", ArmHex: "41524d31", TTLMS: 30000,
		ExpiryOpaque: "00112233445566778899aabbccddeeff", ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("create gc operation: %v", err)
	}
	if err := s.RecordProbeResult("probe-gc", "rct1", "aabbcc"); err != nil {
		t.Fatalf("record gc evidence: %v", err)
	}
	if err := s.SetProbeOperationStatus("probe-gc", string(protocol.OutcomeRejected)); err != nil {
		t.Fatalf("terminalize gc operation: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO probe_results (probe_id, kind, payload_hex, created_at) VALUES (?, 'outcome_acked', 'ack', ?)`, "probe-gc", 1); err != nil {
		t.Fatalf("record gc outcome acknowledgement: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE probe_operations SET updated_at = 1 WHERE id = ?`, "probe-gc"); err != nil {
		t.Fatalf("age gc tombstone: %v", err)
	}
	if err := s.DeleteTerminalProbeOperationsBefore(2); err != nil {
		t.Fatalf("gc terminal probe: %v", err)
	}
	if _, err := s.GetProbeOperation("probe-gc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("gc lookup = %v, want ErrNotFound", err)
	}
	if err := s.SetProbeOperationStatus("probe-gc", string(protocol.OutcomeTimeout)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late status after gc = %v, want ErrNotFound", err)
	}
}

// TestProbeMigrationVersion verifies migration 0004 applied cleanly.
func TestProbeMigrationVersion(t *testing.T) {
	s := openTestStore(t)
	v, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != 7 {
		t.Fatalf("SchemaVersion = %d, want 7 (0001_core..0006_r13_hardening + 0007_traversal)", v)
	}
}

// Exact provider/WAN1/ACK1/RCT1 replay is idempotent, but a different payload
// for the same operation/kind is conflicting evidence. The conflict must not
// overwrite the original journal row or be mistaken for a harmless retry.
func TestRecordProbeResultExactReplayAndConflict(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "n-probe-result")
	mustCreateForward(t, s, Forward{ID: "f-probe-result", NodeID: "n-probe-result", Name: "probe", Protocol: "tcp"})
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: "probe-result-replay", NodeID: "n-probe-result", ForwardID: "f-probe-result",
		ActivationID: "act-1", ProviderID: "provider-1", Status: "IN_FLIGHT",
		Endpoint: "198.51.100.7:8080", ArmHex: "41524d31", TTLMS: 30_000,
		ExpiryOpaque: "00112233445566778899aabbccddeeff", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatalf("create operation: %v", err)
	}

	for _, kind := range []string{"provider", "wan1", "ack1", "rct1"} {
		first := "first-" + kind
		second := "conflict-" + kind
		if err := s.RecordProbeResult("probe-result-replay", kind, first); err != nil {
			t.Fatalf("record %s: %v", kind, err)
		}
		if err := s.RecordProbeResult("probe-result-replay", kind, first); err != nil {
			t.Fatalf("identical %s replay: %v", kind, err)
		}
		if err := s.RecordProbeResult("probe-result-replay", kind, second); !errors.Is(err, ErrProbeDuplicateEvidence) {
			t.Fatalf("conflicting %s replay = %v, want ErrProbeDuplicateEvidence", kind, err)
		}
	}

	results, err := s.ListProbeResults("probe-result-replay")
	if err != nil {
		t.Fatalf("list results: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("result row count = %d, want 4", len(results))
	}
	for _, result := range results {
		want := "first-" + result.Kind
		if result.PayloadHex != want {
			t.Errorf("%s payload = %q, want %q", result.Kind, result.PayloadHex, want)
		}
	}
}
