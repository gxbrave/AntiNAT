package localstate

import (
	"encoding/json"
	"fmt"

	"github.com/gxbrave/AntiNAT/internal/protocol"
	bolt "go.etcd.io/bbolt"
)

type ActivationSnapshot struct {
	ForwardID  string                    `json:"forward_id"`
	Activation string                    `json:"activation"`
	Generation uint64                    `json:"generation"`
	States     protocol.ActivationStates `json:"states"`
}

// SaveActivationSnapshot durably records the local activation mirror before a
// reconnect/restart can reopen a listener. The key is the forward identity so
// stale events cannot overwrite another forward's evidence.
func (s *Store) SaveActivationSnapshot(snapshot ActivationSnapshot) error {
	if snapshot.ForwardID == "" || snapshot.Activation == "" {
		return fmt.Errorf("localstate: activation snapshot identity is required")
	}
	if err := snapshot.States.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketActivation)).Put([]byte(snapshot.ForwardID), raw)
	})
}

func (s *Store) LoadActivationSnapshot(forwardID string) (ActivationSnapshot, bool, error) {
	var snapshot ActivationSnapshot
	var present bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketActivation)).Get([]byte(forwardID))
		if raw == nil {
			return nil
		}
		present = true
		return json.Unmarshal(append([]byte(nil), raw...), &snapshot)
	})
	return snapshot, present, err
}

func (s *Store) ListActivationSnapshots(limit int) ([]ActivationSnapshot, error) {
	if limit <= 0 {
		limit = 256
	}
	out := make([]ActivationSnapshot, 0, limit)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketActivation)).ForEach(func(_, raw []byte) error {
			if len(out) >= limit || raw == nil {
				return nil
			}
			var snapshot ActivationSnapshot
			if err := json.Unmarshal(raw, &snapshot); err != nil {
				return err
			}
			out = append(out, snapshot)
			return nil
		})
	})
	return out, err
}
