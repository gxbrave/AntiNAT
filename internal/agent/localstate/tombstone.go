// Forward delete tombstones (docs/state-model.md §4).
//
// Deletion is always an explicit ABSENT plus a deletion_operation_id; a full
// snapshot that merely omits a Forward never implies deletion. The tombstone
// is written in the same bbolt transaction as the applied-state removal
// (applied.go CommitDesired), before any stop side effect, and is GC'd only
// after the Controller's durable receipt for the deletion operation exists.
package localstate

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ForwardTombstone durably records a Forward deletion intent.
type ForwardTombstone struct {
	ForwardID           string `json:"forward_id"`
	DeletionOperationID string `json:"deletion_operation_id"`
	CreatedAtUnix       int64  `json:"created_at_unix"`
}

// ErrTombstoneNotGCReady reports a tombstone whose deletion operation has not
// yet reached a durable Controller receipt; GC is refused.
var ErrTombstoneNotGCReady = fmt.Errorf("localstate: forward tombstone cannot be GC'd before the deletion operation is durably receipted")

func nowUnix() int64 { return time.Now().Unix() }

// TombstoneExists reports whether a durable tombstone exists for forwardID.
func (s *Store) TombstoneExists(forwardID string) (bool, error) {
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket([]byte(bucketTombstones)).Get([]byte(forwardID)) != nil
		return nil
	})
	return found, err
}

// ListTombstones returns every durable forward tombstone.
func (s *Store) ListTombstones() ([]ForwardTombstone, error) {
	var tombstones []ForwardTombstone
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketTombstones)).ForEach(func(_, raw []byte) error {
			var ts ForwardTombstone
			if err := json.Unmarshal(raw, &ts); err != nil {
				return fmt.Errorf("localstate: decode tombstone: %w", err)
			}
			tombstones = append(tombstones, ts)
			return nil
		})
	})
	return tombstones, err
}
