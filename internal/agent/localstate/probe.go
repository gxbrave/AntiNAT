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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// ArmedProbe is one durable armed probe operation. Deadline is the
// monotonic-clock deadline derived from the arm's ttl_ms. Consumed rows are
// retained as durable replay fences until their control receipt is accepted.
type ArmedProbe struct {
	Arm protocol.ProbeArm
	// ForwardID binds ingress admission to the listener that received the
	// controller arm. It is part of the durable operation, not inferred from
	// the source address or probe id.
	ForwardID   string
	Digest      [32]byte
	Deadline    time.Time
	Consumed    bool
	Receipt     []byte
	ReceiptSent bool
	// ReceiptMessageID retains the historical field name but stores the
	// semantic operation id expected from the controller's receipt payload.
	ReceiptMessageID string
	// ReceiptDeadline bounds a consumed tombstone even if the controller is
	// permanently unavailable.
	ReceiptDeadline time.Time
}

var (
	ErrProbeConsumed = errors.New("localstate: probe id already consumed")
	ErrProbeConflict = errors.New("localstate: probe id conflicts with existing arm")
	ErrProbeNotFound = errors.New("localstate: probe id not found")
)

const defaultProbeScanLimit = 256

// SaveArmedProbe durably persists an armed probe operation. Re-saving the
// same unconsumed probe id replaces the row only when the arm material is
// identical; consumed ids are permanent replay fences.
func (s *Store) SaveArmedProbe(arm protocol.ProbeArm, deadline time.Time) error {
	return s.SaveArmedProbeForForward(arm, "", deadline)
}

// SaveArmedProbeForForward persists an armed operation and its listener
// ownership in one bbolt write. Replays must match both the arm material and
// the forward binding.
func (s *Store) SaveArmedProbeForForward(arm protocol.ProbeArm, forwardID string, deadline time.Time) error {
	rec := ArmedProbe{Arm: arm, ForwardID: forwardID, Digest: arm.Digest(), Deadline: deadline}
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
			if existing.ForwardID != rec.ForwardID || existing.Digest != rec.Digest || !bytes.Equal(existing.Arm.Canonical(), arm.Canonical()) {
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
	return s.MarkArmedProbeConsumedWithReceipt(probeID, receipt, "", time.Now().Add(protocol.ProbeReplayWindow))
}

// MarkArmedProbeConsumedWithReceipt records the deterministic controller
// receipt id and a bounded tombstone deadline in the same bbolt transaction as
// the consumed fence.
func (s *Store) MarkArmedProbeConsumedWithReceipt(probeID [16]byte, receipt []byte, receiptMessageID string, receiptDeadline time.Time) error {
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
			rec.ReceiptMessageID = receiptMessageID
			rec.ReceiptDeadline = receiptDeadline
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

// AcknowledgeArmedProbeReceipt deletes the consumed tombstone identified by
// the controller's deterministic receipt operation id. Missing rows are
// idempotent: a redelivered receipt after GC is harmless. Rows written by the
// previous envelope-id implementation are accepted once, but only when their
// stored receipt bytes derive the same semantic operation id.
func (s *Store) AcknowledgeArmedProbeReceipt(operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		var found []byte
		scanned := 0
		if err := bucket.ForEach(func(k, raw []byte) error {
			if scanned >= defaultProbeScanLimit {
				return nil
			}
			scanned++
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			matches := rec.Consumed && rec.ReceiptMessageID == operationID
			if !matches && rec.Consumed && len(rec.Receipt) != 0 {
				sum := sha256.Sum256(rec.Receipt)
				semanticID := hex.EncodeToString(sum[:])
				legacyID := security.MessageID(semanticID, "probe_ingress_receipt")
				matches = operationID == semanticID && rec.ReceiptMessageID == hex.EncodeToString(legacyID[:])
			}
			if matches {
				found = append([]byte(nil), k...)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("localstate: scan probe receipts: %w", err)
		}
		if found == nil {
			return nil
		}
		return bucket.Delete(found)
	})
}

// SweepArmedProbeTombstones bounds consumed replay fences. Unconsumed rows
// are retained until their arm deadline; consumed rows are retained until the
// controller receipt or the explicit receipt deadline, whichever comes first.
func (s *Store) SweepArmedProbeTombstones(now time.Time) error {
	return s.SweepArmedProbeTombstonesLimit(now, defaultProbeScanLimit)
}

// SweepArmedProbeTombstonesLimit bounds one cleanup transaction. Callers may
// repeat cleanup on subsequent ticks; a single tick must never scan an
// unbounded replay/history bucket.
func (s *Store) SweepArmedProbeTombstonesLimit(now time.Time, limit int) error {
	if limit <= 0 {
		limit = defaultProbeScanLimit
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		var remove [][]byte
		scanned := 0
		if err := bucket.ForEach(func(k, raw []byte) error {
			if scanned >= limit {
				return nil
			}
			scanned++
			var rec ArmedProbe
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			if !rec.Consumed && !now.Before(rec.Deadline) {
				remove = append(remove, append([]byte(nil), k...))
				return nil
			}
			if rec.Consumed && !rec.ReceiptDeadline.IsZero() && !now.Before(rec.ReceiptDeadline) {
				remove = append(remove, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return fmt.Errorf("localstate: scan probe tombstones: %w", err)
		}
		for _, k := range remove {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetArmedProbeReceiptMessageID fills the deterministic receipt id after an
// older process has already consumed the row. It is idempotent and preserves
// the original receipt bytes/deadline.
func (s *Store) SetArmedProbeReceiptMessageID(probeID [16]byte, messageID string, deadline time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketProbeOps))
		raw := bucket.Get(probeID[:])
		if raw == nil {
			return ErrProbeNotFound
		}
		var rec ArmedProbe
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.Consumed {
			if rec.ReceiptMessageID == "" {
				rec.ReceiptMessageID = messageID
			}
			if rec.ReceiptDeadline.IsZero() {
				rec.ReceiptDeadline = deadline
			}
		}
		updated, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return bucket.Put(probeID[:], updated)
	})
}

// ListArmedProbes returns every durable armed operation (expired included;
// the caller filters by deadline). Used for restart recovery and bounded
// sweeping.
func (s *Store) ListArmedProbes() ([]ArmedProbe, error) {
	return s.ListArmedProbesLimit(defaultProbeScanLimit)
}

// ListArmedProbesLimit returns at most limit durable probe rows, keeping
// restart replay and receipt retry work proportional to the bounded active
// operation budget rather than total database history.
func (s *Store) ListArmedProbesLimit(limit int) ([]ArmedProbe, error) {
	if limit <= 0 {
		limit = defaultProbeScanLimit
	}
	var out []ArmedProbe
	err := s.db.View(func(tx *bolt.Tx) error {
		scanned := 0
		return tx.Bucket([]byte(bucketProbeOps)).ForEach(func(_, raw []byte) error {
			if scanned >= limit {
				return nil
			}
			scanned++
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
