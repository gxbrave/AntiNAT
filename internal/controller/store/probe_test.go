package store

import (
	"path/filepath"
	"testing"
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
		ExpiresAt:    1700000000,
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

	if err := s.SetProbeOperationChallenge("probe-1", "cafe"); err != nil {
		t.Fatalf("set challenge: %v", err)
	}
	got, _ = s.GetProbeOperation("probe-1")
	if got.ChallengeHash != "cafe" {
		t.Fatalf("challenge hash not persisted")
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
	if err := s.SetForwardRuntimeStatus("f1", "act-1", `{"wan_reachability_state":"NOT_TESTED"}`); err != nil {
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
	if err := s.SetForwardRuntimeStatus("f1", "act-1", `{"wan_reachability_state":"OPEN_FROM_VANTAGE"}`); err != nil {
		t.Fatalf("update runtime status: %v", err)
	}
	got2, _ := s.GetForwardRuntimeStatus("f1")
	if got2.SnapshotJSON != `{"wan_reachability_state":"OPEN_FROM_VANTAGE"}` {
		t.Fatalf("snapshot not advanced: %+v", got2)
	}

	// A stale activation event (neither the mirror's activation nor the
	// forward's current activation) must be rejected and leave the row
	// untouched.
	if err := s.SetForwardRuntimeStatus("f1", "act-stale", `{"wan_reachability_state":"REJECTED"}`); err == nil {
		t.Fatalf("expected CAS conflict for stale activation event")
	}
	got3, _ := s.GetForwardRuntimeStatus("f1")
	if got3.ActivationID != "act-1" || got3.SnapshotJSON != `{"wan_reachability_state":"OPEN_FROM_VANTAGE"}` {
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
	if err := s.SetForwardRuntimeStatus("f1", "act-2", `{"wan_reachability_state":"NOT_TESTED"}`); err != nil {
		t.Fatalf("set runtime status for current activation: %v", err)
	}
	got4, _ := s.GetForwardRuntimeStatus("f1")
	if got4.ActivationID != "act-2" {
		t.Fatalf("current activation did not replace mirror: %+v", got4)
	}

	// After the mirror moved to act-2, an act-1 event is stale and rejected.
	if err := s.SetForwardRuntimeStatus("f1", "act-1", `{"wan_reachability_state":"REJECTED"}`); err == nil {
		t.Fatalf("expected CAS conflict for old activation after advance")
	}
}

// TestProbeMigrationVersion verifies migration 0004 applied cleanly.
func TestProbeMigrationVersion(t *testing.T) {
	s := openTestStore(t)
	v, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != 5 {
		t.Fatalf("SchemaVersion = %d, want 5 (0001_core + 0002_control + 0003_enrollment + 0004_probe + 0005_probe_hardening)", v)
	}
}
