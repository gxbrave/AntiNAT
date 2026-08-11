package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrStaleSession     = errors.New("stale connection epoch or session")
	ErrMessageConflict  = errors.New("duplicate message ID conflicts with persisted type or payload hash")
	ErrIllegalPhase     = errors.New("illegal outbox phase transition")
	ErrStaleWriter      = errors.New("stale writer attempted to overwrite a persisted semantic result")
	ErrAlreadyReceipted = errors.New("operation was already durably receipted")
)

// Durable outbox phases. Every transition requires its exact predecessor:
//
//	PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC
//
// A semantic ACK never permits GC; only a durable receipt bound to the current
// epoch/session and to a SEMANTIC_ACKED row does. RECEIPTED is recorded as a
// durable tombstone in the receipts bucket immediately before the outbox and
// operation rows are removed, so a replay of a stale receipt cannot resurrect
// or double-GC an operation.
const (
	phasePending       = "PENDING"
	phaseClaimed       = "CLAIMED"
	phaseSent          = "SENT"
	phaseSemanticACKed = "SEMANTIC_ACKED"
	phaseReceipted     = "RECEIPTED"
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

// splitOutboxValue parses the "STATE\x00payload" outbox row. A row without a
// separator (legacy direct writers such as the decommission journal) is
// reported as an unknown phase so that the FSM refuses to operate on it.
func splitOutboxValue(value []byte) (state string, payload []byte) {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		return string(value[:index]), value[index+1:]
	}
	return string(value), nil
}

func outboxPhaseError(operationID, want, got string) error {
	if got == "" {
		return fmt.Errorf("%w: operation %q has no outbox row, want %s", ErrIllegalPhase, operationID, want)
	}
	return fmt.Errorf("%w: operation %q is %s, want %s", ErrIllegalPhase, operationID, got, want)
}

// RecordAndQueueResult records a semantic result as a PENDING outbox entry.
// The write is epoch/session fenced, refuses to overwrite a persisted result
// with a different value (stale-writer fencing), and refuses to resurrect an
// operation that was already durably receipted.
func (s *Store) RecordAndQueueResult(epoch uint64, sessionID, operationID, result string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		operations := tx.Bucket(bucketOperations)
		outbox := tx.Bucket(bucketOutbox)
		receipts := tx.Bucket(bucketReceipts)
		key := []byte(operationID)
		if receipts.Get(key) != nil {
			return fmt.Errorf("%w: operation %q", ErrAlreadyReceipted, operationID)
		}
		if existing := operations.Get(key); existing != nil && string(existing) != result {
			return fmt.Errorf("%w: operation %q result %q conflicts with persisted %q", ErrStaleWriter, operationID, result, string(existing))
		}
		if current := outbox.Get(key); current != nil {
			state, payload := splitOutboxValue(current)
			if state == phasePending && string(payload) == result {
				return nil // idempotent duplicate delivery of the same pending semantic result
			}
			return outboxPhaseError(operationID, phasePending, state)
		}
		if err := operations.Put(key, []byte(result)); err != nil {
			return err
		}
		return outbox.Put(key, append([]byte(phasePending+"\x00"), []byte(result)...))
	})
}

func (s *Store) ClaimOutbox(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket(bucketOutbox)
		key := []byte(operationID)
		value := outbox.Get(key)
		state, payload := splitOutboxValue(value)
		if state != phasePending {
			return outboxPhaseError(operationID, phasePending, state)
		}
		return outbox.Put(key, append([]byte(phaseClaimed+"\x00"), payload...))
	})
}

// MarkOutboxSent advances a claimed operation to SENT (socket write done).
func (s *Store) MarkOutboxSent(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket(bucketOutbox)
		key := []byte(operationID)
		value := outbox.Get(key)
		state, payload := splitOutboxValue(value)
		if state != phaseClaimed {
			return outboxPhaseError(operationID, phaseClaimed, state)
		}
		return outbox.Put(key, append([]byte(phaseSent+"\x00"), payload...))
	})
}

func (s *Store) AcceptSemanticACK(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket(bucketOutbox)
		key := []byte(operationID)
		value := outbox.Get(key)
		state, payload := splitOutboxValue(value)
		if state != phaseSent {
			return outboxPhaseError(operationID, phaseSent, state)
		}
		return outbox.Put(key, append([]byte(phaseSemanticACKed+"\x00"), payload...))
	})
}

// AcceptReceipt durably records a receipt bound to the current epoch/session
// and to a SEMANTIC_ACKED operation, then garbage-collects the outbox and
// operation rows. A premature, stale-session, or duplicate receipt fails
// closed.
func (s *Store) AcceptReceipt(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket(bucketOutbox)
		operations := tx.Bucket(bucketOperations)
		receipts := tx.Bucket(bucketReceipts)
		key := []byte(operationID)
		if receipts.Get(key) != nil {
			return fmt.Errorf("%w: operation %q", ErrAlreadyReceipted, operationID)
		}
		value := outbox.Get(key)
		state, payload := splitOutboxValue(value)
		if state != phaseSemanticACKed {
			return outboxPhaseError(operationID, phaseSemanticACKed, state)
		}
		if err := receipts.Put(key, payload); err != nil {
			return err
		}
		if err := outbox.Delete(key); err != nil {
			return err
		}
		return operations.Delete(key)
	})
}

// OutboxState reports the persisted outbox phase for an operation.
func (s *Store) OutboxState(operationID string) (string, bool, error) {
	state := ""
	present := false
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketOutbox).Get([]byte(operationID))
		if value == nil {
			return nil
		}
		present = true
		state, _ = splitOutboxValue(value)
		return nil
	})
	return state, present, err
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
