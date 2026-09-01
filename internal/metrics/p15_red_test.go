package metrics

import (
	"testing"
	"time"
)

// RED P15 Story 5: traffic deltas must be idempotent and monotonic. A duplicate
// or out-of-order sequence must not inflate a rollup, while legacy connection
// counts remain visible and detailed history can be disabled.
func TestAccumulatorRejectsDuplicateAndOutOfOrderDeltas(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := NewAccumulator(AccumulatorConfig{Now: func() time.Time { return now }, Detailed: true})
	first := TrafficDelta{ForwardID: "fwd-1", Sequence: 2, At: now, BytesIn: 10, BytesOut: 20, LegacyConnectionCount: 3, Completeness: Complete}
	accepted, err := a.Apply(first)
	if err != nil || !accepted {
		t.Fatalf("first delta accepted=%v err=%v", accepted, err)
	}
	if accepted, err := a.Apply(first); err != nil || accepted {
		t.Fatalf("duplicate accepted=%v err=%v", accepted, err)
	}
	old := first
	old.Sequence = 1
	old.BytesIn = 1000
	if accepted, err := a.Apply(old); err != nil || accepted {
		t.Fatalf("out-of-order accepted=%v err=%v", accepted, err)
	}
	rollups := a.Rollups("fwd-1")
	if len(rollups) != 1 || rollups[0].BytesIn != 10 || rollups[0].BytesOut != 20 || rollups[0].LegacyConnectionCount != 3 {
		t.Fatalf("rollups=%+v", rollups)
	}
}

func TestAccumulatorDisabledDetailedHistoryStillRollsUp(t *testing.T) {
	a := NewAccumulator(AccumulatorConfig{Detailed: false})
	accepted, err := a.Apply(TrafficDelta{ForwardID: "fwd-2", Sequence: 1, At: time.Unix(10, 0), BytesIn: 4, BytesOut: 5, Completeness: Complete})
	if err != nil || !accepted {
		t.Fatalf("delta accepted=%v err=%v", accepted, err)
	}
	if got := a.Deltas("fwd-2"); len(got) != 0 {
		t.Fatalf("detailed history retained while disabled: %+v", got)
	}
	if got := a.Rollups("fwd-2"); len(got) != 1 || !got[0].FullyEffective {
		t.Fatalf("rollups=%+v", got)
	}
}
