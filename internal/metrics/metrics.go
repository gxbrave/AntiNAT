// Package metrics contains bounded, deterministic traffic accounting primitives.
package metrics

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrInvalidForwardID    = errors.New("metrics: forward id is required")
	ErrInvalidSequence     = errors.New("metrics: sequence must be positive")
	ErrInvalidCompleteness = errors.New("metrics: completeness must be explicit")
)

// Completeness says whether a traffic report has complete byte accounting.
type Completeness uint8

const (
	Unknown Completeness = iota
	Complete
	Legacy
)

func (c Completeness) Valid() bool { return c == Complete || c == Legacy }

// TrafficDelta is one monotonic agent traffic report. Sequence is scoped to a
// Forward and is the idempotency fence for retries/reconnects.
type TrafficDelta struct {
	ForwardID             string
	Sequence              uint64
	At                    time.Time
	BytesIn               uint64
	BytesOut              uint64
	LegacyConnectionCount uint64
	// Completeness is explicit: Unknown is rejected, Complete is a modern fully
	// effective report, and Legacy is payload-less/partial accounting.
	Completeness Completeness
}

// TrafficRollup is an hourly traffic aggregate. Period is UTC, formatted as
// RFC3339 at the beginning of the hour.
type TrafficRollup struct {
	ForwardID             string    `json:"forward_id"`
	Period                string    `json:"period"`
	BytesIn               uint64    `json:"bytes_in"`
	BytesOut              uint64    `json:"bytes_out"`
	LegacyConnectionCount uint64    `json:"legacy_connection_count"`
	FullyEffective        bool      `json:"fully_effective"`
	UpdatedAt             time.Time `json:"updated_at,omitempty"`
}

// AccumulatorConfig controls an in-memory accumulator. Now is injectable for
// deterministic tests; Detailed controls retention of individual deltas, not
// the durable/hourly aggregate.
type AccumulatorConfig struct {
	Now      func() time.Time
	Detailed bool
}

type Accumulator struct {
	mu       sync.RWMutex
	now      func() time.Time
	detailed bool
	last     map[string]uint64
	deltas   map[string][]TrafficDelta
	rollups  map[string]map[string]TrafficRollup
}

// NewAccumulator returns an empty traffic accumulator.
func NewAccumulator(cfg AccumulatorConfig) *Accumulator {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Accumulator{
		now: now, detailed: cfg.Detailed,
		last: make(map[string]uint64), deltas: make(map[string][]TrafficDelta),
		rollups: make(map[string]map[string]TrafficRollup),
	}
}

// Apply accepts a delta exactly once. Duplicate and older sequences are
// harmless replays and return accepted=false without changing any aggregate.
func (a *Accumulator) Apply(delta TrafficDelta) (accepted bool, err error) {
	if delta.ForwardID == "" {
		return false, ErrInvalidForwardID
	}
	if delta.Sequence == 0 {
		return false, ErrInvalidSequence
	}
	if delta.Completeness != Complete && delta.Completeness != Legacy {
		return false, ErrInvalidCompleteness
	}
	if delta.At.IsZero() {
		delta.At = a.now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if delta.Sequence <= a.last[delta.ForwardID] {
		return false, nil
	}
	a.last[delta.ForwardID] = delta.Sequence
	period := delta.At.UTC().Truncate(time.Hour).Format(time.RFC3339)
	if a.rollups[delta.ForwardID] == nil {
		a.rollups[delta.ForwardID] = make(map[string]TrafficRollup)
	}
	r := a.rollups[delta.ForwardID][period]
	r.ForwardID = delta.ForwardID
	r.Period = period
	r.BytesIn += delta.BytesIn
	r.BytesOut += delta.BytesOut
	if delta.LegacyConnectionCount > r.LegacyConnectionCount {
		r.LegacyConnectionCount = delta.LegacyConnectionCount
	}
	// Modern reports are fully effective; any legacy report makes the affected
	// rollup explicitly partial until a later complete period is observed.
	if r.UpdatedAt.IsZero() {
		r.FullyEffective = delta.Completeness == Complete
	} else {
		r.FullyEffective = r.FullyEffective && delta.Completeness == Complete
	}
	r.UpdatedAt = a.now()
	a.rollups[delta.ForwardID][period] = r
	if a.detailed {
		a.deltas[delta.ForwardID] = append(a.deltas[delta.ForwardID], delta)
	}
	return true, nil
}

// Deltas returns a snapshot of retained detailed deltas, ordered by sequence.
func (a *Accumulator) Deltas(forwardID string) []TrafficDelta {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := append([]TrafficDelta(nil), a.deltas[forwardID]...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

// Rollups returns a snapshot ordered by period.
func (a *Accumulator) Rollups(forwardID string) []TrafficRollup {
	a.mu.RLock()
	defer a.mu.RUnlock()
	byPeriod := a.rollups[forwardID]
	out := make([]TrafficRollup, 0, len(byPeriod))
	for _, r := range byPeriod {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Period < out[j].Period })
	return out
}

// SetDetailed changes only future detail retention. Existing deltas are kept
// until explicitly discarded, so callers can safely report legacy counts.
func (a *Accumulator) SetDetailed(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.detailed = enabled
}

// LastSequence returns the accepted high-water sequence for a Forward.
func (a *Accumulator) LastSequence(forwardID string) uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.last[forwardID]
}
