// Received desired state and per-Forward applied state (docs/state-model.md
// §2, v0.8 §6.4 / §7.1).
//
// CommitDesired applies a desired snapshot with one atomic bbolt transaction
// and per-resource PARTIAL semantics: an apply failure retains the Forward's
// old applied record while its siblings advance. A desired snapshot that
// merely omits a Forward never implies deletion; only an explicit ABSENT with
// a deletion_operation_id does (and that path writes a durable tombstone,
// tombstone.go).
package localstate

import (
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ApplyOutcome is the per-resource result of reconciling one desired Forward.
type ApplyOutcome int

const (
	// ApplyApplied records a newly applied Forward state.
	ApplyApplied ApplyOutcome = iota
	// ApplyFailed retains the old applied state (hook/apply error).
	ApplyFailed
	// ApplyDeleted writes the durable tombstone and removes applied state.
	ApplyDeleted
)

// ForwardApply is one per-Forward decision handed to CommitDesired. Exactly
// one outcome per Forward in the desired snapshot is required.
type ForwardApply struct {
	ForwardID string
	Outcome   ApplyOutcome
	// Applied is set for ApplyApplied and must itself pass
	// protocol.AppliedForwardState.Validate.
	Applied *protocol.AppliedForwardState
	// Err carries the apply error for ApplyFailed.
	Err error
}

// ApplyStatus summarizes a CommitDesired batch.
type ApplyStatus int

const (
	// ApplyStatusFull means no Forward failed to apply.
	ApplyStatusFull ApplyStatus = iota
	// ApplyStatusPartial means some Forwards applied while others failed.
	ApplyStatusPartial
	// ApplyStatusFailed means no Forward made progress.
	ApplyStatusFailed
)

func (s ApplyStatus) String() string {
	switch s {
	case ApplyStatusFull:
		return "FULL"
	case ApplyStatusPartial:
		return "PARTIAL"
	case ApplyStatusFailed:
		return "FAILED"
	}
	return "UNKNOWN"
}

// ApplyReport summarizes a CommitDesired batch.
type ApplyReport struct {
	Status         ApplyStatus
	AppliedCount   int
	DeletedCount   int
	FailedCount    int
	FailedForwards []string
}

// CommitDesired atomically persists a received desired snapshot together with
// the per-Forward decisions: applied records for successes, tombstones plus
// applied-state removal for explicit deletions, and untouched old applied
// records for failures. The whole batch is one transaction: any invalid
// outcome fails the commit closed with no partial writes.
func (s *Store) CommitDesired(d protocol.DesiredState, outcomes []ForwardApply) (ApplyReport, error) {
	if err := d.Validate(); err != nil {
		return ApplyReport{}, fmt.Errorf("localstate: desired: %w", err)
	}
	specs := make(map[string]protocol.ForwardSpec, len(d.Forwards))
	for _, f := range d.Forwards {
		specs[f.ForwardID] = f
	}
	if len(outcomes) != len(d.Forwards) {
		return ApplyReport{}, fmt.Errorf("localstate: commit needs %d outcomes for %d desired Forwards", len(outcomes), len(d.Forwards))
	}
	seen := make(map[string]bool, len(outcomes))
	for _, o := range outcomes {
		spec, ok := specs[o.ForwardID]
		if !ok {
			return ApplyReport{}, fmt.Errorf("localstate: outcome for unknown forward %q", o.ForwardID)
		}
		if seen[o.ForwardID] {
			return ApplyReport{}, fmt.Errorf("localstate: duplicate outcome for forward %q", o.ForwardID)
		}
		seen[o.ForwardID] = true
		switch o.Outcome {
		case ApplyApplied:
			if o.Applied == nil {
				return ApplyReport{}, fmt.Errorf("localstate: forward %q Applied outcome carries no applied state", o.ForwardID)
			}
			if err := o.Applied.Validate(); err != nil {
				return ApplyReport{}, fmt.Errorf("localstate: forward %q: %w", o.ForwardID, err)
			}
			if o.Applied.ForwardID != o.ForwardID {
				return ApplyReport{}, fmt.Errorf("localstate: applied record forward_id %q does not match outcome %q", o.Applied.ForwardID, o.ForwardID)
			}
			if spec.Presence != protocol.PresencePresent {
				return ApplyReport{}, fmt.Errorf("localstate: Applied outcome for forward %q whose desired presence is %q", o.ForwardID, spec.Presence)
			}
		case ApplyDeleted:
			if spec.Presence != protocol.PresenceAbsent || spec.DeletionOperationID == "" {
				return ApplyReport{}, fmt.Errorf("localstate: Deleted outcome for forward %q requires desired ABSENT with deletion_operation_id", o.ForwardID)
			}
		case ApplyFailed:
			// Old applied state is retained; nothing to validate.
		default:
			return ApplyReport{}, fmt.Errorf("localstate: forward %q has unknown outcome %d", o.ForwardID, o.Outcome)
		}
	}

	var report ApplyReport
	err := s.db.Update(func(tx *bolt.Tx) error {
		desiredBucket := tx.Bucket([]byte(bucketDesired))
		appliedBucket := tx.Bucket([]byte(bucketApplied))
		tombstoneBucket := tx.Bucket([]byte(bucketTombstones))

		raw, err := json.Marshal(d)
		if err != nil {
			return err
		}
		if err := desiredBucket.Put([]byte(d.NodeID), raw); err != nil {
			return err
		}

		for _, o := range outcomes {
			spec := specs[o.ForwardID]
			key := []byte(o.ForwardID)
			switch o.Outcome {
			case ApplyApplied:
				// A durable deletion tombstone is authoritative: an old snapshot
				// or Controller rollback must never resurrect this Forward.
				if tx.Bucket([]byte(bucketTombstones)).Get(key) != nil {
					return fmt.Errorf("%w: forward %q", ErrTombstonedForward, o.ForwardID)
				}
				raw, err := json.Marshal(o.Applied)
				if err != nil {
					return err
				}
				if err := appliedBucket.Put(key, raw); err != nil {
					return err
				}
				report.AppliedCount++
			case ApplyDeleted:
				tombstone := ForwardTombstone{
					ForwardID:           o.ForwardID,
					DeletionOperationID: spec.DeletionOperationID,
					CreatedAtUnix:       nowUnix(),
				}
				raw, err := json.Marshal(tombstone)
				if err != nil {
					return err
				}
				// Tombstone and applied-state removal are the same bbolt
				// transaction (state-model §4): a crash cannot leave the
				// Forward applied but un-tombstoned, or tombstoned but still
				// applied.
				if err := tombstoneBucket.Put(key, raw); err != nil {
					return err
				}
				if err := appliedBucket.Delete(key); err != nil {
					return err
				}
				report.DeletedCount++
			case ApplyFailed:
				if o.Err != nil {
					report.FailedForwards = append(report.FailedForwards, o.ForwardID)
				}
				report.FailedCount++
			}
		}
		return nil
	})
	if err != nil {
		return ApplyReport{}, err
	}
	switch {
	case report.FailedCount == 0:
		report.Status = ApplyStatusFull
	case report.AppliedCount+report.DeletedCount > 0:
		report.Status = ApplyStatusPartial
	default:
		report.Status = ApplyStatusFailed
	}
	return report, nil
}

// SaveReceivedDesired persists a received desired snapshot without applying
// it. The transport layer stores the message here; the reconcile loop applies
// it later.
func (s *Store) SaveReceivedDesired(d protocol.DesiredState) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("localstate: desired: %w", err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketDesired)).Put([]byte(d.NodeID), raw)
	})
}

// LoadReceivedDesired returns the last received desired snapshot for the
// node, if any.
func (s *Store) LoadReceivedDesired() (protocol.DesiredState, bool, error) {
	var d protocol.DesiredState
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketDesired)).ForEach(func(k, raw []byte) error {
			if found {
				return errors.New("localstate: multiple received desired snapshots in one Agent store")
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return fmt.Errorf("localstate: decode received desired: %w", err)
			}
			found = true
			return nil
		})
	})
	return d, found, err
}

// GetAppliedState returns the durable applied record for one Forward.
func (s *Store) GetAppliedState(forwardID string) (protocol.AppliedForwardState, bool, error) {
	var state protocol.AppliedForwardState
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketApplied)).Get([]byte(forwardID))
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("localstate: decode applied state for %q: %w", forwardID, err)
		}
		found = true
		return nil
	})
	return state, found, err
}

// ListAppliedStates returns every durable applied Forward record.
func (s *Store) ListAppliedStates() ([]protocol.AppliedForwardState, error) {
	var states []protocol.AppliedForwardState
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketApplied)).ForEach(func(_, raw []byte) error {
			var state protocol.AppliedForwardState
			if err := json.Unmarshal(raw, &state); err != nil {
				return fmt.Errorf("localstate: decode applied state: %w", err)
			}
			states = append(states, state)
			return nil
		})
	})
	return states, err
}
