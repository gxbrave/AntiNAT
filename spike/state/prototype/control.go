package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrStaleSession    = errors.New("stale connection epoch or session")
	ErrMessageConflict = errors.New("duplicate message ID conflicts with persisted type or payload hash")
)

var (
	keyCurrentEpoch   = []byte("current_epoch")
	keyCurrentSession = []byte("current_session")
)

func encodeEpoch(epoch uint64) []byte {
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, epoch)
	return value
}

func decodeEpoch(value []byte) uint64 {
	if len(value) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func (s *Store) AdvanceSession(epoch uint64, sessionID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketSession)
		currentEpoch := decodeEpoch(bucket.Get(keyCurrentEpoch))
		currentSession := string(bucket.Get(keyCurrentSession))
		if epoch < currentEpoch || (epoch == currentEpoch && currentSession != "" && currentSession != sessionID) {
			return ErrStaleSession
		}
		if epoch == currentEpoch && currentSession == sessionID {
			return nil
		}
		if err := bucket.Put(keyCurrentEpoch, encodeEpoch(epoch)); err != nil {
			return err
		}
		return bucket.Put(keyCurrentSession, []byte(sessionID))
	})
}

func checkSession(tx *bolt.Tx, epoch uint64, sessionID string) error {
	bucket := tx.Bucket(bucketSession)
	if decodeEpoch(bucket.Get(keyCurrentEpoch)) != epoch || string(bucket.Get(keyCurrentSession)) != sessionID {
		return ErrStaleSession
	}
	return nil
}

func (s *Store) ReceiveCommand(epoch uint64, sessionID, messageID, messageType, payloadHash string) (bool, error) {
	duplicate := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		bucket := tx.Bucket(bucketInbox)
		key := []byte(messageID)
		identity := []byte(messageType + "\x00" + payloadHash)
		if existing := bucket.Get(key); existing != nil {
			if !bytes.Equal(existing, identity) {
				return ErrMessageConflict
			}
			duplicate = true
			return nil
		}
		return bucket.Put(key, identity)
	})
	return duplicate, err
}

func (s *Store) ClaimOutbox(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket(bucketOutbox)
		value := outbox.Get([]byte(operationID))
		if value == nil {
			return fmt.Errorf("outbox operation %q not found", operationID)
		}
		return outbox.Put([]byte(operationID), append([]byte("CLAIMED\x00"), resultPayload(value)...))
	})
}

func (s *Store) RecordAndQueueResult(operationID, result string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketOperations).Put([]byte(operationID), []byte(result)); err != nil {
			return err
		}
		return tx.Bucket(bucketOutbox).Put([]byte(operationID), []byte("PENDING\x00"+result))
	})
}

func resultPayload(value []byte) []byte {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		return value[index+1:]
	}
	return value
}

func (s *Store) ResultForSession(epoch uint64, sessionID, operationID string) (string, error) {
	var result string
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		value := tx.Bucket(bucketOperations).Get([]byte(operationID))
		if value == nil {
			return fmt.Errorf("operation result %q not found", operationID)
		}
		result = string(value)
		return nil
	})
	return result, err
}

func (s *Store) AcceptSemanticACK(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket(bucketOutbox)
		value := outbox.Get([]byte(operationID))
		if value == nil {
			return fmt.Errorf("outbox operation %q not found", operationID)
		}
		return outbox.Put([]byte(operationID), append([]byte("SEMANTIC_ACKED\x00"), resultPayload(value)...))
	})
}

func (s *Store) AcceptReceipt(operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketOutbox).Delete([]byte(operationID)); err != nil {
			return err
		}
		return tx.Bucket(bucketOperations).Delete([]byte(operationID))
	})
}

func (s *Store) OutboxContains(operationID string) bool {
	present := false
	if err := s.db.View(func(tx *bolt.Tx) error {
		present = tx.Bucket(bucketOutbox).Get([]byte(operationID)) != nil
		return nil
	}); err != nil {
		return false
	}
	return present
}
