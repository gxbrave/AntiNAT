// Durable armed probe operations (schema v2, docs/protocol.md §7.2).
//
// The agent persists each outstanding probe operation with its monotonic
// deadline BEFORE answering probe_armed (RDY1). A crash mid-probe therefore
// never loses an armed operation: on restart the controller can re-request
// the provider without re-arming, and the ingress gate refuses frames whose
// operation is gone.
package localstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ArmedProbe is one durable armed probe operation. Deadline is the
// monotonic-clock deadline derived from the arm's ttl_ms. Consumed rows are
// retained as durable replay fences until their control receipt is accepted.
type ArmedProbe struct {
	Arm         protocol.ProbeArm
	Digest      [32]byte
	Deadline    time.Time
	Consumed    bool
	Receipt     []byte
	ReceiptSent bool
}

var (
	ErrProbeConsumed = errors.New("localstate: probe id already consumed")
	ErrProbeConflict = errors.New("localstate: probe id conflicts with existing arm")
	ErrProbeNotFound = errors.New("localstate: probe id not found")
)

// SaveArmedProbe durably persists an armed probe operation. Re-saving the
// same unconsumed probe id replaces the row only when the arm material is
// identical; consumed ids are permanent replay fences.
func (s *Store) SaveArmedProbe(arm protocol.ProbeArm, deadline time.Time) error {
	rec := ArmedProbe{Arm: arm, Digest: arm.Digest(), Deadline: deadline}
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("localstate: encode armed probe: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		if old := bucket.Get(arm.ProbeID[:]); old != nil {
			var existing ArmedProbe
			if err := json.Unmarshal(old, &existing); err != nil {
				return fmt.Errorf("localstate: decode existing armed probe: %w", err)
			}
			if existing.Consumed {
				return ErrProbeConsumed
			}
			if existing.Digest != rec.Digest || !bytes.Equal(existing.Arm.Canonical(), arm.Canonical()) {
				return ErrProbeConflict
			}
		}
		return bucket.Put(arm.ProbeID[:], raw)
	})
}

// LoadArmedProbe returns the armed operation for a probe id, if present.
func (s *Store) LoadArmedProbe(probeID [16]byte) (ArmedProbe, bool, error) {
	var rec ArmedProbe
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketProbeOps)).Get(probeID[:])
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		found = true
		return nil
	})
	return rec, found, err
}

// DeleteArmedProbe removes an operation (normally only an expired row).
func (s *Store) DeleteArmedProbe(probeID [16]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketProbeOps)).Delete(probeID[:])
	})
}

// MarkArmedProbeConsumed durably records the receipt before any network ACK
// or control-channel send. A consumed probe id can therefore never be rearmed
// after a process crash, and a failed receipt send can be retried later.
func (s *Store) MarkArmedProbeConsumed(probeID [16]byte, receipt []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		if !rec.Consumed {
			rec.Consumed = true
			rec.Receipt = append([]byte(nil), receipt...)
			rec.ReceiptSent = false
		}
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode consumed probe: %w", err)
		}
		return bucket.Put(probeID[:], updated)
	})
}

// MarkArmedProbeReceiptSent records that the durable receipt was accepted by
// the control-channel sender. The consumed row remains as a replay fence.
func (s *Store) MarkArmedProbeReceiptSent(probeID [16]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("localstate: decode armed probe: %w", err)
		}
		rec.ReceiptSent = true
		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("localstate: encode receipted probe: %w", err)
		}
		return bucket.Put(probeID[:], updated)
	})
}

// ListArmedProbes returns every durable armed operation (expired included;
// the caller filters by deadline). Used for restart recovery and bounded
// sweeping.
func (s *Store) ListArmedProbes() ([]ArmedProbe, error) {
	var out []ArmedProbe
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketProbeOps)).ForEach(func(_, raw []byte) error {
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return fmt.Errorf("localstate: decode armed probe: %w", err)
			}
			out = append(out, rec)
			return nil
		})
	})
	return out, err
}
