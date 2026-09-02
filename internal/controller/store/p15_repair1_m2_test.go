package store_test

// P15 repair cycle-1 M2 disposition guard: the reviewer's finding ("detailed
// disabled must not persist rollups") contradicts the P15-established metrics
// semantics (TestAccumulatorDisabledDetailedHistoryStillRollsUp: deltas are
// optional, hourly rollups remain durable regardless). The store behavior is
// therefore reviewed & not applicable; this test pins the established
// semantics so a future change cannot silently break store/metrics
// consistency.

import (
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair1M2TrafficDetailedDisabledStillRollsUp(t *testing.T) {
	s := openRepairStore(t)
	mustNodeRepair(t, s, "node-t")
	if _, err := s.CreateForward(store.Forward{ID: "fwd-t", NodeID: "node-t", Name: "web", Protocol: "tcp"}); err != nil {
		t.Fatalf("CreateForward: %v", err)
	}

	// Detailed retention is off by default: per-delta history is not kept, the
	// hourly rollup still is.
	ok, err := s.ApplyTrafficDelta(store.TrafficDelta{ForwardID: "fwd-t", Sequence: 1, BytesIn: 100, BytesOut: 50, FullyEffective: true})
	if err != nil || !ok {
		t.Fatalf("delta (detailed off) = ok %v err %v", ok, err)
	}
	if rows, err := s.ListTrafficDeltas("fwd-t", 10, 0); err != nil || len(rows) != 0 {
		t.Fatalf("delta rows with detailed off = %d err %v, want 0 (mostly-empty history)", len(rows), err)
	}
	if n, err := s.TrafficRollupCount("fwd-t"); err != nil || n != 1 {
		t.Fatalf("rollup count with detailed off = %d err %v, want 1 (rollups durable regardless)", n, err)
	}

	// Enabling detailed retention adds per-delta rows; the rollup still exists.
	if err := s.SetTrafficDetailed("fwd-t", true); err != nil {
		t.Fatalf("SetTrafficDetailed: %v", err)
	}
	if on, err := s.TrafficDetailed("fwd-t"); err != nil || !on {
		t.Fatalf("TrafficDetailed = %v err %v, want true", on, err)
	}
	if ok, err := s.ApplyTrafficDelta(store.TrafficDelta{ForwardID: "fwd-t", Sequence: 2, BytesIn: 200, BytesOut: 25, FullyEffective: true}); err != nil || !ok {
		t.Fatalf("delta (detailed on) = ok %v err %v", ok, err)
	}
	if rows, err := s.ListTrafficDeltas("fwd-t", 10, 0); err != nil || len(rows) != 1 {
		t.Fatalf("delta rows with detailed on = %d err %v, want 1", len(rows), err)
	}
	if n, err := s.TrafficRollupCount("fwd-t"); err != nil || n != 1 {
		t.Fatalf("rollup count with detailed on = %d err %v, want 1", n, err)
	}
}
