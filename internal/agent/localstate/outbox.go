// Outbox enumeration helper (P08 extension of the declared P07 control
// persistence interface). The journal stores semantic payloads keyed by
// operation id; the transport needs the full pending set to drive the outbox
// pump after reconnect (RequeueOutboxForSession resets rows to PENDING, then
// the pump re-envelopes each one).
package localstate

import bolt "go.etcd.io/bbolt"

// OutboxOperationIDs returns every operation id with a durable outbox row
// (any FSM phase). Bounded by the operation set; used by the transport pump.
func (s *Store) OutboxOperationIDs() ([]string, error) {
	var ids []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketOutbox)).ForEach(func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	})
	return ids, err
}
