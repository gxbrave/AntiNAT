// Durable armed probe operations (schema v2, docs/protocol.md §7.2).
//
// The agent persists each outstanding probe operation with its monotonic
// deadline BEFORE answering probe_armed (RDY1). A crash mid-probe therefore
// never loses an armed operation: on restart the controller can re-request
// the provider without re-arming, and the ingress gate refuses frames whose
// operation is gone.
package localstate

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ArmedProbe is one durable armed probe operation. Deadline is the
// monotonic-clock deadline derived from the arm's ttl_ms.
type ArmedProbe struct {
	Arm      protocol.ProbeArm
	Digest   [32]byte
	Deadline time.Time
}

// SaveArmedProbe durably persists an armed probe operation. Re-saving the
// same probe id replaces the row (idempotent re-arm with identical material).
func (s *Store) SaveArmedProbe(arm protocol.ProbeArm, deadline time.Time) error {
	rec := ArmedProbe{Arm: arm, Digest: arm.Digest(), Deadline: deadline}
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("localstate: encode armed probe: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketProbeOps)).Put(arm.ProbeID[:], raw)
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

// DeleteArmedProbe removes an armed operation (consumed or expired).
func (s *Store) DeleteArmedProbe(probeID [16]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketProbeOps)).Delete(probeID[:])
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
