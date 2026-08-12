// Per-resource desired apply (P07 Story 2 through the reconcile layer).
//
// ApplyDesired turns a received desired snapshot into per-Forward decisions
// with PARTIAL semantics: one Forward's apply failure retains its old applied
// record while siblings advance. An old desired revision is idempotently
// skipped (no side effect), a durable tombstone is authoritative (never
// resurrect), the terminal latch blocks new actors after the marker engages,
// and ABSENT deletes commit the tombstone before the stop hook runs
// (tombstone-before-stop).
package reconcile

import (
	"context"
	"errors"
	"fmt"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ApplyHook starts/applies one PRESENT Forward and returns its durable applied
// state. The real data plane (P09) fills the actual bind tuple, mapping
// journal reference, and recovery descriptor; a nil hook leaves PRESENT
// Forwards untouched (no data plane wired yet).
type ApplyHook func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error)

// StopHook stops one deleted Forward's actor. It runs only after the durable
// tombstone commit, so a crash between the commit and the stop can never
// resurrect the Forward (state-model §4 tombstone-before-stop).
type StopHook func(ctx context.Context, forwardID string) error

// DesiredOutcome is the per-Forward reconcile decision.
type DesiredOutcome int

const (
	OutcomeApplied DesiredOutcome = iota
	OutcomeUnchanged
	OutcomeFailed
	OutcomeTombstonedRejected
	OutcomeTerminalRejected
	OutcomeDeleted
	OutcomeDeleteFailed
)

func (o DesiredOutcome) String() string {
	switch o {
	case OutcomeApplied:
		return "APPLIED"
	case OutcomeUnchanged:
		return "UNCHANGED"
	case OutcomeFailed:
		return "FAILED"
	case OutcomeTombstonedRejected:
		return "TOMBSTONED_REJECTED"
	case OutcomeTerminalRejected:
		return "TERMINAL_REJECTED"
	case OutcomeDeleted:
		return "DELETED"
	case OutcomeDeleteFailed:
		return "DELETE_FAILED"
	}
	return "UNKNOWN"
}

// DesiredApplyResult is one per-Forward reconcile decision.
type DesiredApplyResult struct {
	ForwardID string
	Outcome   DesiredOutcome
	Err       error
}

// DesiredApplyReport summarizes one ApplyDesired pass.
type DesiredApplyReport struct {
	Status  localstate.ApplyStatus
	Results []DesiredApplyResult
}

// ErrDecommissioned reports reconcile work attempted on a DECOMMISSIONED
// Agent; only cleanup is allowed from that marker onward.
var ErrDecommissioned = errors.New("reconcile: agent is decommissioned")

// ApplyDesired reconciles one desired snapshot against the applied state.
func ApplyDesired(ctx context.Context, store *localstate.Store, latch *localstate.Latch, d protocol.DesiredState, apply ApplyHook, stop StopHook) (DesiredApplyReport, error) {
	var report DesiredApplyReport
	if err := d.Validate(); err != nil {
		return report, fmt.Errorf("reconcile: desired: %w", err)
	}
	applied, err := store.ListAppliedStates()
	if err != nil {
		return report, err
	}
	prevByID := make(map[string]protocol.AppliedForwardState, len(applied))
	for _, s := range applied {
		prevByID[s.ForwardID] = s
	}

	results := make([]DesiredApplyResult, 0, len(d.Forwards))
	commits := make([]localstate.ForwardApply, 0, len(d.Forwards))

	for _, spec := range d.Forwards {
		switch spec.Presence {
		case protocol.PresenceAbsent:
			results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeDeleted})
			commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplyDeleted})
		case protocol.PresencePresent:
			if prev, ok := prevByID[spec.ForwardID]; ok && spec.DesiredRevision <= prev.DesiredRevision {
				// Old revision: already applied at this or a newer revision;
				// idempotent skip, no side effect, no actor restart.
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeUnchanged})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			if latch.Engaged() {
				// The terminal marker has started: no concurrent desired
				// apply may start a new actor (state-model §3.4).
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeTerminalRejected})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			tombstoned, err := store.TombstoneExists(spec.ForwardID)
			if err != nil {
				return report, err
			}
			if tombstoned {
				// A durable tombstone is authoritative: an old snapshot or
				// Controller rollback must never resurrect this Forward.
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeTombstonedRejected})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			if apply == nil {
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeUnchanged})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			appliedState, applyErr := apply(ctx, spec)
			if applyErr != nil {
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeFailed, Err: applyErr})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplyFailed, Err: applyErr})
				continue
			}
			results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeApplied})
			commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplyApplied, Applied: &appliedState})
		}
	}

	// One atomic commit: received desired + applied records + tombstones.
	if _, err := store.CommitDesired(d, commits); err != nil {
		return report, err
	}

	// Tombstone-before-stop: only now that the tombstone is durable do the
	// stop hooks run.
	for i := range results {
		if results[i].Outcome != OutcomeDeleted || stop == nil {
			continue
		}
		if err := stop(ctx, results[i].ForwardID); err != nil {
			results[i].Outcome = OutcomeDeleteFailed
			results[i].Err = err
		}
	}

	var anyFailed, anyProgress bool
	for _, r := range results {
		switch r.Outcome {
		case OutcomeFailed, OutcomeDeleteFailed:
			anyFailed = true
		case OutcomeApplied, OutcomeDeleted:
			anyProgress = true
		}
	}
	switch {
	case !anyFailed:
		report.Status = localstate.ApplyStatusFull
	case anyProgress:
		report.Status = localstate.ApplyStatusPartial
	default:
		report.Status = localstate.ApplyStatusFailed
	}
	report.Results = results
	return report, nil
}
