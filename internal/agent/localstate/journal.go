// Durable control inbox/outbox and operation journals
// (docs/state-model.md §3, v0.8 §6.4).
//
// The outbox FSM is PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED
// (then GC). SENT means only that the socket write happened; a semantic ACK
// never permits GC, only a durable receipt bound to the current epoch/session
// and to a SEMANTIC_ACKED row does. The inbox/operation FSM is
// RECEIVED -> INTENT_PERSISTED -> APPLYING -> APPLIED | NACKED, and
// delete/decommission/rotation/restore persist intent before any external
// side effect. Every mutation is epoch/session fenced; old-epoch ACKs are
// rejected and the same semantic result is re-enveloped on the new session.
//
// All rows are semantic payloads — never session-bound signed frames — so a
// reconnect re-signs the same result without repeating the side effect
// (v0.8 §6.1).
package localstate

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// Journal error sentinels.
var (
	// ErrStaleSession rejects any mutation from an old connection epoch or
	// session after a newer one has been accepted.
	ErrStaleSession = errors.New("localstate: stale connection epoch or session")
	// ErrMessageConflict rejects a duplicate message ID whose type or payload
	// hash differs from the persisted row (v0.8 §6.1).
	ErrMessageConflict = errors.New("localstate: duplicate message ID conflicts with persisted type or payload hash")
	// ErrIllegalPhase rejects an FSM transition that is not the exact
	// predecessor single step.
	ErrIllegalPhase = errors.New("localstate: illegal journal phase transition")
	// ErrStaleWriter rejects an overwrite of a persisted semantic result with
	// a different value.
	ErrStaleWriter = errors.New("localstate: stale writer attempted to overwrite a persisted semantic result")
	// ErrAlreadyReceipted rejects any resurrection of an operation that was
	// already durably receipted.
	ErrAlreadyReceipted = errors.New("localstate: operation was already durably receipted")
	// ErrOperationConflict rejects reusing an operation ID for different
	// message material.
	ErrOperationConflict = errors.New("localstate: operation ID conflicts with persisted message material")
	// ErrOperationNotFound reports a missing operation journal or result.
	ErrOperationNotFound = errors.New("localstate: operation not found")
)

// Outbox FSM phases (docs/state-model.md §3.1). RECEIPTED is only ever a
// short-lived durable marker inside AcceptReceipt; the durable receipt
// tombstone lives in the operation_results bucket.
const (
	phasePending       = "PENDING"
	phaseClaimed       = "CLAIMED"
	phaseSent          = "SENT"
	phaseSemanticACKed = "SEMANTIC_ACKED"
)

// Inbox/operation FSM phases (docs/state-model.md §3.2).
const (
	phaseReceived        = "RECEIVED"
	phaseIntentPersisted = "INTENT_PERSISTED"
	phaseApplying        = "APPLYING"
	phaseApplied         = "APPLIED"
	phaseNacked          = "NACKED"
)

// Key prefixes inside the operation_results bucket. The result payload is the
// bare operation ID key; the operation journal and the durable receipt
// tombstone use reserved prefixes so one frozen bucket carries all three.
var (
	keyOpJournal = []byte("op:")
	keyReceipt   = []byte("receipt:")
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

// inboxEntry is the durable per-message-ID delivery dedup row.
type inboxEntry struct {
	MessageType string `json:"message_type"`
	PayloadHash string `json:"payload_hash"`
	OperationID string `json:"operation_id"`
}

// operationJournal is the per-operation inbox FSM row.
type operationJournal struct {
	Kind      string `json:"kind"`
	MessageID string `json:"message_id"`
	Phase     string `json:"phase"`
	Reason    string `json:"reason,omitempty"`
}

// CurrentSession returns the accepted connection epoch and session ID.
func (s *Store) CurrentSession() (uint64, string, error) {
	var epoch uint64
	var session string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketEpochs))
		epoch = decodeEpoch(b.Get(keyCurrentEpoch))
		session = string(b.Get(keyCurrentSession))
		return nil
	})
	return epoch, session, err
}

// AdvanceSession durably accepts a new connection epoch/session, refusing a
// lower epoch and a different session at the same epoch.
func (s *Store) AdvanceSession(epoch uint64, sessionID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketEpochs))
		currentEpoch := decodeEpoch(b.Get(keyCurrentEpoch))
		currentSession := string(b.Get(keyCurrentSession))
		if epoch < currentEpoch || (epoch == currentEpoch && currentSession != "" && currentSession != sessionID) {
			return ErrStaleSession
		}
		if epoch == currentEpoch && currentSession == sessionID {
			return nil
		}
		if err := b.Put(keyCurrentEpoch, encodeEpoch(epoch)); err != nil {
			return err
		}
		return b.Put(keyCurrentSession, []byte(sessionID))
	})
}

func checkSession(tx *bolt.Tx, epoch uint64, sessionID string) error {
	b := tx.Bucket([]byte(bucketEpochs))
	if decodeEpoch(b.Get(keyCurrentEpoch)) != epoch || string(b.Get(keyCurrentSession)) != sessionID {
		return ErrStaleSession
	}
	return nil
}

func opJournalKey(operationID string) []byte {
	return append(append([]byte{}, keyOpJournal...), operationID...)
}
func receiptKey(operationID string) []byte {
	return append(append([]byte{}, keyReceipt...), operationID...)
}

func (s *Store) loadOperationJournal(tx *bolt.Tx, operationID string) (operationJournal, bool, error) {
	raw := tx.Bucket([]byte(bucketOperations)).Get(opJournalKey(operationID))
	if raw == nil {
		return operationJournal{}, false, nil
	}
	var j operationJournal
	if err := json.Unmarshal(raw, &j); err != nil {
		return operationJournal{}, false, fmt.Errorf("localstate: decode operation journal %q: %w", operationID, err)
	}
	return j, true, nil
}

func operationPhaseError(operationID, want string, j operationJournal) error {
	if j.Phase == "" {
		return fmt.Errorf("%w: operation %q has no journal row, want %s", ErrIllegalPhase, operationID, want)
	}
	return fmt.Errorf("%w: operation %q is %s, want %s", ErrIllegalPhase, operationID, j.Phase, want)
}

// ReceiveCommand durably records an incoming command message. The same
// message ID with the same type and payload hash is a cached duplicate; the
// same message ID (or operation ID) with different material fails closed.
func (s *Store) ReceiveCommand(epoch uint64, sessionID, operationID, messageID, messageType, payloadHash, kind string) (bool, error) {
	duplicate := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		ops := tx.Bucket([]byte(bucketOperations))
		if ops.Get(receiptKey(operationID)) != nil {
			return fmt.Errorf("%w: operation %q", ErrAlreadyReceipted, operationID)
		}
		inbox := tx.Bucket([]byte(bucketInbox))
		key := []byte(messageID)
		if existing := inbox.Get(key); existing != nil {
			var entry inboxEntry
			if err := json.Unmarshal(existing, &entry); err != nil {
				return fmt.Errorf("localstate: decode inbox entry %q: %w", messageID, err)
			}
			if entry.MessageType != messageType || entry.PayloadHash != payloadHash {
				return fmt.Errorf("%w: message %q (type=%s hash=%s) vs persisted (type=%s hash=%s)", ErrMessageConflict, messageID, messageType, payloadHash, entry.MessageType, entry.PayloadHash)
			}
			duplicate = true
			return nil
		}
		if j, ok, err := s.loadOperationJournal(tx, operationID); err != nil {
			return err
		} else if ok {
			if j.Kind != kind || j.MessageID != messageID {
				return fmt.Errorf("%w: operation %q (kind=%s msg=%s) vs persisted (kind=%s msg=%s)", ErrOperationConflict, operationID, kind, messageID, j.Kind, j.MessageID)
			}
			duplicate = true
			return nil
		}
		entry := inboxEntry{MessageType: messageType, PayloadHash: payloadHash, OperationID: operationID}
		rawEntry, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := inbox.Put(key, rawEntry); err != nil {
			return err
		}
		journal := operationJournal{Kind: kind, MessageID: messageID, Phase: phaseReceived}
		rawJournal, err := json.Marshal(journal)
		if err != nil {
			return err
		}
		return ops.Put(opJournalKey(operationID), rawJournal)
	})
	return duplicate, err
}

// PersistOperationIntent advances an operation RECEIVED -> INTENT_PERSISTED.
// Intent is persisted before any external side effect (state-model §3.2).
func (s *Store) PersistOperationIntent(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		j, ok, err := s.loadOperationJournal(tx, operationID)
		if err != nil {
			return err
		}
		if !ok || j.Phase != phaseReceived {
			return operationPhaseError(operationID, phaseReceived, j)
		}
		j.Phase = phaseIntentPersisted
		return s.putOperationJournal(tx, operationID, j)
	})
}

// MarkOperationApplying advances an operation INTENT_PERSISTED -> APPLYING.
func (s *Store) MarkOperationApplying(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		j, ok, err := s.loadOperationJournal(tx, operationID)
		if err != nil {
			return err
		}
		if !ok || j.Phase != phaseIntentPersisted {
			return operationPhaseError(operationID, phaseIntentPersisted, j)
		}
		j.Phase = phaseApplying
		return s.putOperationJournal(tx, operationID, j)
	})
}

// CompleteOperation advances an operation APPLYING -> APPLIED and, in the
// same transaction, durably records the semantic result and queues it to the
// outbox as PENDING.
func (s *Store) CompleteOperation(epoch uint64, sessionID, operationID string, result []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		j, ok, err := s.loadOperationJournal(tx, operationID)
		if err != nil {
			return err
		}
		if !ok || j.Phase != phaseApplying {
			return operationPhaseError(operationID, phaseApplying, j)
		}
		j.Phase = phaseApplied
		if err := s.putOperationJournal(tx, operationID, j); err != nil {
			return err
		}
		return s.recordResultAndQueue(tx, operationID, result)
	})
}

// NackOperation advances an operation APPLYING -> NACKED with a reason.
func (s *Store) NackOperation(epoch uint64, sessionID, operationID, reason string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		j, ok, err := s.loadOperationJournal(tx, operationID)
		if err != nil {
			return err
		}
		if !ok || j.Phase != phaseApplying {
			return operationPhaseError(operationID, phaseApplying, j)
		}
		j.Phase = phaseNacked
		j.Reason = reason
		return s.putOperationJournal(tx, operationID, j)
	})
}

func (s *Store) putOperationJournal(tx *bolt.Tx, operationID string, j operationJournal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(bucketOperations)).Put(opJournalKey(operationID), raw)
}

// OperationPhase reports the persisted inbox/operation FSM phase.
func (s *Store) OperationPhase(operationID string) (string, bool, error) {
	var phase string
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		j, found, err := s.loadOperationJournal(tx, operationID)
		if err != nil {
			return err
		}
		if found {
			phase, ok = j.Phase, true
		}
		return nil
	})
	return phase, ok, err
}

// splitOutboxValue parses the "STATE\x00payload" outbox row.
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

// recordResultAndQueue durably records a semantic result and queues it as a
// PENDING outbox row, within the caller's transaction. It refuses to
// resurrect a receipted operation. An existing outbox row in ANY phase
// (PENDING/CLAIMED/SENT/SEMANTIC_ACKED, no durable receipt yet) means the
// semantic result is already durably recorded AND queued for delivery; the
// re-record is tolerated without touching the row — even for a different
// payload, because the Controller re-issues with a fresh operation ID when
// it needs a different outcome (state-model §3.2: the same semantic result
// is re-signed without repeating the side effect). This preserves the
// fail-closed guard against silently OVERWRITING a persisted semantic
// result: the durable row is never mutated in place, and a different payload
// with no queued row still fails closed (ErrStaleWriter). The strict
// single-step FSM for Claim/Sent/ACK/Receipt remains enforced by the
// transport-facing transitions.
func (s *Store) recordResultAndQueue(tx *bolt.Tx, operationID string, result []byte) error {
	ops := tx.Bucket([]byte(bucketOperations))
	outbox := tx.Bucket([]byte(bucketOutbox))
	key := []byte(operationID)
	if ops.Get(receiptKey(operationID)) != nil {
		return fmt.Errorf("%w: operation %q", ErrAlreadyReceipted, operationID)
	}
	if current := outbox.Get(key); current != nil {
		return nil // already durably queued: tolerate, never mutate the row
	}
	if existing := ops.Get(key); existing != nil && !bytes.Equal(existing, result) {
		return fmt.Errorf("%w: operation %q result %q conflicts with persisted %q", ErrStaleWriter, operationID, result, existing)
	}
	if err := ops.Put(key, result); err != nil {
		return err
	}
	return outbox.Put(key, append(append([]byte(phasePending), 0), result...))
}

// QueueResult records a semantic result and queues it as a PENDING outbox
// entry outside the inbox FSM path (e.g. reconcile recording a deletion
// result keyed by deletion_operation_id). Same fencing as
// recordResultAndQueue.
func (s *Store) QueueResult(epoch uint64, sessionID, operationID string, result []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		return s.recordResultAndQueue(tx, operationID, result)
	})
}

// ClaimOutbox advances PENDING -> CLAIMED.
func (s *Store) ClaimOutbox(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket([]byte(bucketOutbox))
		key := []byte(operationID)
		state, payload := splitOutboxValue(outbox.Get(key))
		if state != phasePending {
			return outboxPhaseError(operationID, phasePending, state)
		}
		return outbox.Put(key, append(append([]byte(phaseClaimed), 0), payload...))
	})
}

// MarkOutboxSent advances CLAIMED -> SENT (socket write done).
func (s *Store) MarkOutboxSent(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket([]byte(bucketOutbox))
		key := []byte(operationID)
		state, payload := splitOutboxValue(outbox.Get(key))
		if state != phaseClaimed {
			return outboxPhaseError(operationID, phaseClaimed, state)
		}
		return outbox.Put(key, append(append([]byte(phaseSent), 0), payload...))
	})
}

// AcceptSemanticACK advances SENT -> SEMANTIC_ACKED. A semantic ACK never
// permits GC.
func (s *Store) AcceptSemanticACK(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket([]byte(bucketOutbox))
		key := []byte(operationID)
		state, payload := splitOutboxValue(outbox.Get(key))
		if state != phaseSent {
			return outboxPhaseError(operationID, phaseSent, state)
		}
		return outbox.Put(key, append(append([]byte(phaseSemanticACKed), 0), payload...))
	})
}

// AcceptReceipt durably records a receipt bound to the current epoch/session
// and to a SEMANTIC_ACKED row, then garbage-collects the outbox, operation
// result, operation journal, and the control_inbox dedup row in the same
// transaction. The receipt tombstone stays so a replayed record cannot
// resurrect the operation. A premature, stale-session, or duplicate receipt
// fails closed.
func (s *Store) AcceptReceipt(epoch uint64, sessionID, operationID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		ops := tx.Bucket([]byte(bucketOperations))
		outbox := tx.Bucket([]byte(bucketOutbox))
		key := []byte(operationID)
		if ops.Get(receiptKey(operationID)) != nil {
			return fmt.Errorf("%w: operation %q", ErrAlreadyReceipted, operationID)
		}
		value := outbox.Get(key)
		state, payload := splitOutboxValue(value)
		if state != phaseSemanticACKed {
			return outboxPhaseError(operationID, phaseSemanticACKed, state)
		}
		// Capture the operation journal's message ID before it is deleted so
		// the corresponding control_inbox dedup row can be GC'd in this same
		// transaction (bounded inbox growth over the Agent lifetime). Rows
		// queued outside the inbox FSM (QueueResult) have no journal and no
		// inbox row to delete.
		var messageID string
		if j, ok, err := s.loadOperationJournal(tx, operationID); err != nil {
			return err
		} else if ok {
			messageID = j.MessageID
		}
		if err := ops.Put(receiptKey(operationID), payload); err != nil {
			return err
		}
		if err := outbox.Delete(key); err != nil {
			return err
		}
		if err := ops.Delete(key); err != nil {
			return err
		}
		if err := ops.Delete(opJournalKey(operationID)); err != nil {
			return err
		}
		if messageID != "" {
			if err := tx.Bucket([]byte(bucketInbox)).Delete([]byte(messageID)); err != nil {
				return err
			}
		}
		return nil
	})
}

// RequeueOutboxForSession resets every non-PENDING, non-receipted outbox row
// to PENDING for the current session so the same semantic result is
// re-enveloped and re-signed without repeating any side effect. Returns the
// number of rows requeued.
func (s *Store) RequeueOutboxForSession(epoch uint64, sessionID string) (int, error) {
	count := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		outbox := tx.Bucket([]byte(bucketOutbox))
		return outbox.ForEach(func(k, value []byte) error {
			state, payload := splitOutboxValue(value)
			if state == phasePending {
				return nil
			}
			if err := outbox.Put(k, append(append([]byte(phasePending), 0), payload...)); err != nil {
				return err
			}
			count++
			return nil
		})
	})
	return count, err
}

// OutboxState reports the persisted outbox phase for an operation.
func (s *Store) OutboxState(operationID string) (string, bool, error) {
	state := ""
	present := false
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket([]byte(bucketOutbox)).Get([]byte(operationID))
		if value == nil {
			return nil
		}
		present = true
		state, _ = splitOutboxValue(value)
		return nil
	})
	return state, present, err
}

// OutboxContains reports whether an outbox row exists for an operation.
func (s *Store) OutboxContains(operationID string) bool {
	present := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		present = tx.Bucket([]byte(bucketOutbox)).Get([]byte(operationID)) != nil
		return nil
	})
	return present
}

// ResultForOperation returns the durable semantic result for the current
// session. A receipted operation reports ErrAlreadyReceipted.
func (s *Store) ResultForOperation(epoch uint64, sessionID, operationID string) ([]byte, error) {
	var result []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := checkSession(tx, epoch, sessionID); err != nil {
			return err
		}
		ops := tx.Bucket([]byte(bucketOperations))
		if ops.Get(receiptKey(operationID)) != nil {
			return fmt.Errorf("%w: operation %q", ErrAlreadyReceipted, operationID)
		}
		value := ops.Get([]byte(operationID))
		if value == nil {
			return fmt.Errorf("%w: operation %q result", ErrOperationNotFound, operationID)
		}
		result = append([]byte(nil), value...)
		return nil
	})
	return result, err
}

// ReceiptExists reports whether a durable receipt tombstone exists.
func (s *Store) ReceiptExists(operationID string) (bool, error) {
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket([]byte(bucketOperations)).Get(receiptKey(operationID)) != nil
		return nil
	})
	return found, err
}
