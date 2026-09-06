package metrics

import (
	"errors"
	"testing"
	"time"
)

func TestAccumulatorRequiresExplicitCompleteness(t *testing.T) {
	a := NewAccumulator(AccumulatorConfig{})
	if _, err := a.Apply(TrafficDelta{ForwardID: "fwd", Sequence: 1}); !errors.Is(err, ErrInvalidCompleteness) {
		t.Fatalf("unknown completeness error=%v, want ErrInvalidCompleteness", err)
	}
}

func TestAccumulatorLegacyRollupIsPartialAndDoesNotInflate(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	a := NewAccumulator(AccumulatorConfig{Now: func() time.Time { return clock }, Detailed: true})
	if _, err := a.Apply(TrafficDelta{ForwardID: "fwd", Sequence: 1, At: clock, BytesIn: 7, BytesOut: 8, LegacyConnectionCount: 4, Completeness: Legacy}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(TrafficDelta{ForwardID: "fwd", Sequence: 2, At: clock, BytesIn: 3, BytesOut: 2, LegacyConnectionCount: 5, Completeness: Complete}); err != nil {
		t.Fatal(err)
	}
	rollups := a.Rollups("fwd")
	if len(rollups) != 1 || rollups[0].BytesIn != 10 || rollups[0].BytesOut != 10 || rollups[0].LegacyConnectionCount != 5 || rollups[0].FullyEffective {
		t.Fatalf("rollups=%+v, want one partial aggregate", rollups)
	}
	if len(a.Deltas("fwd")) != 2 {
		t.Fatalf("deltas=%d, want 2", len(a.Deltas("fwd")))
	}
}

func TestAccumulatorFakeClockPeriodsAndOrdering(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	a := NewAccumulator(AccumulatorConfig{Now: func() time.Time { return clock }, Detailed: true})
	for seq, at := range []time.Time{clock.Add(2 * time.Hour), clock, clock.Add(time.Hour)} {
		if _, err := a.Apply(TrafficDelta{ForwardID: "fwd", Sequence: uint64(seq + 1), At: at, BytesIn: 1, Completeness: Complete}); err != nil {
			t.Fatal(err)
		}
	}
	got := a.Rollups("fwd")
	if len(got) != 3 || got[0].Period >= got[1].Period || got[1].Period >= got[2].Period {
		t.Fatalf("period ordering=%+v", got)
	}
}
