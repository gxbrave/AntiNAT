package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// P08-owned store extension: the controller-side control FSM methods. P06
// created the control_outbox/control_inbox tables and the enqueue/count/get
// surface; the per-session claim/send/ack/receipt transitions and the inbox
// dedup are the P08-declared additions consumed by the agent hub (frozen
// state-model §3.1, protocol.md §3.5).

// Control-plane FSM sentinels mirroring the agent journal semantics.
var (
	// ErrIllegalPhase rejects an FSM transition that is not the exact
	// predecessor single step.
	ErrIllegalPhase = errors.New("store: illegal control outbox phase transition")
	// ErrStaleSession rejects a transition from a session that is not the
	// row's binding session (old-epoch ACK rejection).
	ErrStaleSession = errors.New("store: control transition from a stale session")
	// ErrMessageConflict rejects a duplicate message_id with different node,
	// operation, type, or payload (fail-closed session conflict, protocol.md §3.5).
	ErrMessageConflict = errors.New("store: control inbox message id conflict")
)

// ControlInboxItem is one durable inbound A2C message record.
type ControlInboxItem struct {
	ID              int64
	MessageID       string
	NodeID          string
	MessageType     string
	OperationID     string
	SemanticPayload string
	State           string
}

// ClaimControlOutbox atomically advances up to limit PENDING rows for a node
// to CLAIMED bound to the session and returns the claimed items in id order.
func (s *Store) ClaimControlOutbox(nodeID, sessionID string, limit int) ([]ControlOutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	// Claim is a read-then-write operation. A deferred SQLite transaction can
	// let two sessions read the same PENDING snapshot and then fail with
	// SQLITE_BUSY while upgrading, rather than deterministically letting one
	// session own the rows. BEGIN IMMEDIATE serializes the claim decision at
	// the write boundary, just like the other idempotent store operations.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("store: outbox claim conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return nil, fmt.Errorf("store: begin outbox claim: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	rows, err := conn.QueryContext(context.Background(),
		`SELECT id, operation_id, message_type, node_id, semantic_payload, state
		   FROM control_outbox
		  WHERE node_id = ? AND state = 'PENDING'
		  ORDER BY id ASC LIMIT ?`, nodeID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: query pending outbox: %w", err)
	}
	var items []ControlOutboxItem
	var ids []int64
	for rows.Next() {
		var item ControlOutboxItem
		var id int64
		if err := rows.Scan(&id, &item.OperationID, &item.MessageType, &item.NodeID,
			&item.SemanticPayload, &item.State); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan pending outbox: %w", err)
		}
		items = append(items, item)
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: pending outbox rows: %w", err)
	}
	for _, id := range ids {
		res, err := conn.ExecContext(context.Background(),
			`UPDATE control_outbox SET state = 'CLAIMED', session_id = ?, updated_at = ?
			  WHERE id = ? AND state = 'PENDING'`,
			sessionID, now(), id,
		)
		if err != nil {
			return nil, fmt.Errorf("store: claim outbox row: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("store: claim outbox row count: %w", err)
		}
		if n != 1 {
			return nil, fmt.Errorf("%w: outbox row %d was claimed concurrently", ErrIllegalPhase, id)
		}
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return nil, fmt.Errorf("store: commit outbox claim: %w", err)
	}
	committed = true
	for i := range items {
		items[i].State = "CLAIMED"
	}
	return items, nil
}

// outboxTransition applies a single-step FSM transition to the row identified
// by (operation_id, message_type), verifying the session binding.
func (s *Store) outboxTransition(operationID, messageType, sessionID, want, next string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox
		    SET state = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = ? AND session_id = ?`,
		next, now(), operationID, messageType, want, sessionID,
	)
	if err != nil {
		return fmt.Errorf("store: outbox transition %s->%s: %w", want, next, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: outbox transition rows: %w", err)
	}
	if n == 0 {
		// Distinguish stale session from illegal phase.
		var session string
		err := s.db.QueryRow(
			`SELECT session_id FROM control_outbox
			  WHERE operation_id = ? AND message_type = ?`,
			operationID, messageType,
		).Scan(&session)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
		}
		if err != nil {
			return err
		}
		if session != sessionID {
			return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, session)
		}
		return fmt.Errorf("%w: operation %q is not %s", ErrIllegalPhase, operationID, want)
	}
	return nil
}

// MarkControlOutboxSent advances CLAIMED -> SENT (socket write done).
func (s *Store) MarkControlOutboxSent(operationID, messageType, sessionID string) error {
	// Verify session binding first: the transition must not advance a row
	// claimed by another session.
	var bound string
	err := s.db.QueryRow(
		`SELECT session_id FROM control_outbox
		  WHERE operation_id = ? AND message_type = ?`, operationID, messageType,
	).Scan(&bound)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
	}
	if err != nil {
		return err
	}
	if bound != sessionID {
		return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, bound)
	}
	return s.outboxTransition(operationID, messageType, sessionID, "CLAIMED", "SENT")
}

// AcceptControlSemanticACK advances SENT -> SEMANTIC_ACKED. A semantic ACK
// never permits GC.
func (s *Store) AcceptControlSemanticACK(operationID, messageType, sessionID string) error {
	return s.outboxTransition(operationID, messageType, sessionID, "SENT", "SEMANTIC_ACKED")
}

// AcceptControlReceipt advances SEMANTIC_ACKED -> RECEIPTED and GCs the row
// (the durable receipt is recorded in control_inbox; the outbox row is
// deleted so the outbox stays bounded).
func (s *Store) AcceptControlReceipt(operationID, messageType, sessionID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin outbox receipt: %w", err)
	}
	defer tx.Rollback()

	var state, session, nodeID string
	err = tx.QueryRow(
		`SELECT state, session_id, node_id FROM control_outbox
		  WHERE operation_id = ? AND message_type = ?`, operationID, messageType,
	).Scan(&state, &session, &nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
	}
	if err != nil {
		return err
	}
	if session != sessionID {
		return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, session)
	}
	if state != "SEMANTIC_ACKED" {
		return fmt.Errorf("%w: operation %q is %s, want SEMANTIC_ACKED", ErrIllegalPhase, operationID, state)
	}
	// A forward deletion issued as a desired/forward_delete command has two
	// durable semantic results: the normal command report and the dedicated
	// deletion result queued by the reconciler. The indexed outbox row is the
	// only durable join point between those result message IDs. Do not GC it
	// when the first result's receipt arrives; otherwise the second result can
	// no longer be correlated after a normal fast agent pump. Non-deletion
	// commands retain the ordinary one-result receipt semantics.
	if messageType == "desired" || messageType == "forward_delete" {
		var deletionCount int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM forward_deletion_operations WHERE id = ?`, operationID,
		).Scan(&deletionCount); err != nil {
			return fmt.Errorf("store: check deletion result fan-in: %w", err)
		}
		if deletionCount == 1 {
			var commandResultID, controllerResultID string
			if err := tx.QueryRow(`
				SELECT operation_complete_message_id, controller_operation_complete_message_id
				  FROM control_outbox
				 WHERE operation_id = ? AND message_type = ?`, operationID, messageType,
			).Scan(&commandResultID, &controllerResultID); err != nil {
				return fmt.Errorf("store: read deletion result fan-in ids: %w", err)
			}
			var resultCount int
			if err := tx.QueryRow(`
				SELECT COUNT(*) FROM control_inbox
				 WHERE node_id = ? AND message_id IN (?, ?)`,
				nodeID, commandResultID, controllerResultID,
			).Scan(&resultCount); err != nil {
				return fmt.Errorf("store: check deletion result fan-in rows: %w", err)
			}
			if resultCount < 2 {
				if err := tx.Commit(); err != nil {
					return fmt.Errorf("store: commit retained deletion outbox: %w", err)
				}
				return nil
			}
		}
	}
	if _, err := tx.Exec(
		`UPDATE control_outbox SET state = 'RECEIPTED', updated_at = ? WHERE operation_id = ? AND message_type = ?`,
		now(), operationID, messageType,
	); err != nil {
		return fmt.Errorf("store: mark outbox receipted: %w", err)
	}
	// A terminal probe outcome needs a durable acknowledgement fence that
	// survives outbox GC. Keep it in the operation's evidence rows so the
	// marker is removed atomically with the terminal tombstone, while a crash
	// between receipt processing and recovery cannot cause a duplicate command.
	if messageType == "probe_outcome" {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO probe_results (probe_id, kind, payload_hex, created_at)
			 VALUES (?, 'outcome_acked', 'ack', ?)`, operationID, now(),
		); err != nil {
			return fmt.Errorf("store: record probe outcome acknowledgement: %w", err)
		}
		res, err := tx.Exec(
			`UPDATE probe_terminal_deliveries SET disposition = 'DELIVERED', updated_at = ?
			 WHERE probe_id = ? AND disposition = 'ENQUEUED'`,
			now(), operationID,
		)
		if err != nil {
			return fmt.Errorf("store: mark probe outcome delivered: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("store: mark probe outcome delivered rows: %w", err)
		} else if n != 1 {
			return fmt.Errorf("%w: probe outcome %q delivery is not ENQUEUED", ErrIllegalPhase, operationID)
		}
	}
	// GC: the outbox row is removed; the durable record lives in control_inbox.
	if _, err := tx.Exec(
		`DELETE FROM control_outbox WHERE operation_id = ? AND message_type = ?`,
		operationID, messageType,
	); err != nil {
		return fmt.Errorf("store: gc outbox row: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit outbox receipt: %w", err)
	}
	return nil
}

// ProbeOutcomeAcknowledged reports whether the terminal activation command was
// durably consumed by the agent. The marker is intentionally separate from the
// control outbox row because receipt processing deletes that row.
func (s *Store) ProbeOutcomeAcknowledged(operationID string) (bool, error) {
	var marker int
	err := s.db.QueryRow(
		`SELECT 1 FROM probe_results WHERE probe_id = ? AND kind = 'outcome_acked' LIMIT 1`,
		operationID,
	).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: query probe outcome acknowledgement: %w", err)
	}
	return marker == 1, nil
}

// RequeueControlOutboxForSession resets every in-flight row of the node to
// PENDING so a new session re-envelopes the same semantic payload (v0.8
// §6.1). Only CLAIMED/SENT rows are requeued: a SEMANTIC_ACKED row is the
// controller's own proof that the agent's result was already processed and
// the C2A receipt written, so re-delivering it could hand the agent a
// command it has already durably receipted (journal tombstone fails closed
// with ErrAlreadyReceipted and kills the session). SEMANTIC_ACKED rows are
// healed by the result-resend path (RebindControlOutboxSession) or, for
// rows whose A2C receipt was lost, left for the receipt-TTL sweeper (P14
// lifecycle scope). Returns the number of rows requeued.
func (s *Store) RequeueControlOutboxForSession(nodeID, sessionID string) (int, error) {
	res, err := s.db.Exec(
		`UPDATE control_outbox
		    SET state = 'PENDING', session_id = ?, updated_at = ?
		  WHERE node_id = ? AND state IN ('CLAIMED', 'SENT')`,
		sessionID, now(), nodeID,
	)
	if err != nil {
		return 0, fmt.Errorf("store: requeue outbox for session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: requeue outbox rows: %w", err)
	}
	return int(n), nil
}

// RebindControlOutboxSession re-binds a SEMANTIC_ACKED row to the session
// that resends its result. The authenticated, deduped result resend proves
// the new session is continuing the operation, so the follow-up A2C receipt
// from that session may complete the GC; without the re-bind the receipt
// would be rejected as stale-session and kill the session. The FSM state is
// untouched (no advance past SEMANTIC_ACKED); any other state fails closed.
func (s *Store) RebindControlOutboxSession(operationID, messageType, sessionID string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox SET session_id = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = 'SEMANTIC_ACKED'`,
		sessionID, now(), operationID, messageType,
	)
	if err != nil {
		return fmt.Errorf("store: rebind outbox session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rebind outbox rows: %w", err)
	}
	if n == 0 {
		var state string
		err := s.db.QueryRow(
			`SELECT state FROM control_outbox
			  WHERE operation_id = ? AND message_type = ?`,
			operationID, messageType,
		).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: operation %q is %s, want SEMANTIC_ACKED", ErrIllegalPhase, operationID, state)
	}
	return nil
}

// RecordControlInbox durably records an inbound A2C message. message_id is
// UNIQUE (protocol.md §3.5): the same id + same node/operation/type/payload is
// a cached duplicate (returned true); any different binding or material is a
// fail-closed conflict. INSERT OR IGNORE makes the first-write decision
// atomic, so concurrent redelivery cannot leak a UNIQUE constraint error.
func (s *Store) RecordControlInbox(item ControlInboxItem) (bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO control_inbox
		    (message_id, node_id, message_type, semantic_payload, state,
		     operation_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'RECEIVED', ?, ?, ?)`,
		item.MessageID, item.NodeID, item.MessageType, item.SemanticPayload,
		item.OperationID, s.currentUnix(), s.currentUnix(),
	)
	if err != nil {
		return false, fmt.Errorf("store: record control inbox: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: record control inbox rows: %w", err)
	}
	if n == 1 {
		return false, nil
	}

	var existingNodeID, existingMessageType, existingOperationID, existingPayload string
	err = s.db.QueryRow(
		`SELECT node_id, message_type, COALESCE(operation_id, ''), semantic_payload
		   FROM control_inbox WHERE message_id = ?`, item.MessageID,
	).Scan(&existingNodeID, &existingMessageType, &existingOperationID, &existingPayload)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("store: control inbox row disappeared after duplicate insert")
	}
	if err != nil {
		return false, fmt.Errorf("store: get control inbox: %w", err)
	}
	if existingNodeID != item.NodeID || existingMessageType != item.MessageType ||
		existingOperationID != item.OperationID || existingPayload != item.SemanticPayload {
		return false, fmt.Errorf("%w: message %q binding/material differs from persisted row", ErrMessageConflict, item.MessageID)
	}
	return true, nil
}

// SetControlInboxState records completion of a durable inbound message's
// downstream handling. RECEIVED rows are intentionally retained for replay
// correlation; a sink failure leaves the row RECEIVED so a deterministic
// redelivery can retry the sink, while PROCESSED rows suppress duplicate
// forwarding.
func (s *Store) SetControlInboxState(messageID, state string) error {
	if messageID == "" || state == "" {
		return errors.New("store: control inbox state requires message id and state")
	}
	res, err := s.db.Exec(
		`UPDATE control_inbox SET state = ?, updated_at = ? WHERE message_id = ?`,
		state, s.currentUnix(), messageID,
	)
	if err != nil {
		return fmt.Errorf("store: set control inbox state: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set control inbox state rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// ControlInboxState returns the durable downstream-processing state for one
// inbound message.
func (s *Store) ControlInboxState(messageID string) (string, error) {
	var state string
	err := s.db.QueryRow(`SELECT state FROM control_inbox WHERE message_id = ?`, messageID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: get control inbox state: %w", err)
	}
	return state, nil
}

const (
	maxControlInboxCleanupBatch = 1024
	maxControlInboxCleanupScan  = 4096
)

// DeleteControlInboxBeforeLimit reclaims processed control-inbox tombstones
// older than the replay cutoff in bounded, high-water passes. A high-water ID
// is captured before selecting candidates, so rows arriving during cleanup are
// never accidentally consumed by the same pass. Rows that still back a live
// outbox/deletion/probe replay fence are retained even when they are old.
func (s *Store) DeleteControlInboxBeforeLimit(cutoff int64, limit int) (int, error) {
	limit = probeCleanupLimit(limit)
	if limit > maxControlInboxCleanupBatch {
		limit = maxControlInboxCleanupBatch
	}
	scanLimit := limit
	if scanLimit <= maxControlInboxCleanupScan/4 {
		scanLimit *= 4
	} else {
		scanLimit = maxControlInboxCleanupScan
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin control inbox cleanup: %w", err)
	}
	defer tx.Rollback()
	var highWater int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM control_inbox`).Scan(&highWater); err != nil {
		return 0, fmt.Errorf("store: read control inbox cleanup high-water: %w", err)
	}
	if highWater == 0 {
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("store: commit empty control inbox cleanup: %w", err)
		}
		return 0, nil
	}
	rows, err := tx.Query(`SELECT id, message_id, node_id, message_type,
		COALESCE(operation_id, ''), semantic_payload, state
		FROM control_inbox
		WHERE id <= ? AND state = 'PROCESSED' AND updated_at < ?
		ORDER BY id LIMIT ?`, highWater, cutoff, scanLimit)
	if err != nil {
		return 0, fmt.Errorf("store: select control inbox cleanup candidates: %w", err)
	}
	var candidates []ControlInboxItem
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.ID, &item.MessageID, &item.NodeID,
			&item.MessageType, &item.OperationID, &item.SemanticPayload, &item.State); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: scan control inbox cleanup candidate: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("store: close control inbox cleanup candidates: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: read control inbox cleanup candidates: %w", err)
	}
	removed := 0
	for _, item := range candidates {
		protected, err := controlInboxRetentionProtected(tx, item)
		if err != nil {
			return 0, err
		}
		if protected {
			continue
		}
		res, err := tx.Exec(`DELETE FROM control_inbox
			WHERE id = ? AND id <= ? AND state = 'PROCESSED' AND updated_at < ?`,
			item.ID, highWater, cutoff)
		if err != nil {
			return 0, fmt.Errorf("store: delete control inbox row %d: %w", item.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("store: delete control inbox row count %d: %w", item.ID, err)
		}
		removed += int(n)
		if removed >= limit {
			break
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit control inbox cleanup: %w", err)
	}
	return removed, nil
}

// controlInboxRetentionProtected keeps a processed tombstone while a later
// reconnect/result path still needs it. All checks run on the cleanup
// transaction so the dependency decision and delete share one SQLite snapshot.
func controlInboxRetentionProtected(tx *sql.Tx, item ControlInboxItem) (bool, error) {
	operationID, deletionID, probeID := controlInboxPayloadIDs(item.SemanticPayload)
	if item.OperationID != "" {
		if operationID == "" {
			operationID = item.OperationID
		}
		if probeID == "" && item.MessageType == "probe_result" {
			probeID = item.OperationID
		}
	}
	outboxFence, err := controlInboxOutboxFence(tx, item.NodeID, item.OperationID, operationID, item.MessageID)
	if err != nil {
		return false, err
	}
	if outboxFence {
		return true, nil
	}

	switch item.MessageType {
	case "operation_complete":
		return controlInboxPendingDeletionFence(tx, item, deletionID)
	case "probe_result":
		if probeID == "" {
			// A processed result without a durable operation discriminator cannot
			// be proven safe to discard; retain it fail-closed.
			return true, nil
		}
		return controlInboxLiveProbeFenceByID(tx, probeID)
	case "probe_ingress_receipt":
		return controlInboxLiveProbeReceiptFence(tx, item)
	default:
		return false, nil
	}
}

// controlInboxOutboxFence protects command/result/receipt tombstones while
// their semantic outbox row is still resendable. Correlation IDs are compared
// against both the transport operation discriminator and the deterministic
// message IDs; no payload-derived value is used to authorize a new operation.
func controlInboxOutboxFence(tx *sql.Tx, nodeID string, operationID ...string) (bool, error) {
	ids := make([]string, 3)
	for i := range ids {
		if i < len(operationID) {
			ids[i] = operationID[i]
		}
	}
	if ids[0] == "" && ids[1] == "" && ids[2] == "" {
		return false, nil
	}
	var live int
	err := tx.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM control_outbox o
		 WHERE o.node_id = ? AND (
			o.operation_id IN (?, ?, ?)
			OR o.command_message_id IN (?, ?, ?)
			OR o.operation_complete_message_id IN (?, ?, ?)
			OR o.controller_operation_complete_message_id IN (?, ?, ?)
		 )
	)`, nodeID,
		ids[0], ids[1], ids[2], ids[0], ids[1], ids[2], ids[0], ids[1], ids[2], ids[0], ids[1], ids[2]).Scan(&live)
	if err != nil {
		return false, fmt.Errorf("store: check control inbox outbox fence: %w", err)
	}
	return live != 0, nil
}

func controlInboxPayloadIDs(payload string) (operationID, deletionID, probeID string) {
	var v struct {
		OperationID         string `json:"operation_id"`
		DeletionOperationID string `json:"deletion_operation_id"`
		ProbeID             string `json:"probe_id"`
	}
	if len(payload) == 0 || json.Unmarshal([]byte(payload), &v) != nil {
		return "", "", ""
	}
	return v.OperationID, v.DeletionOperationID, v.ProbeID
}

func controlInboxPendingDeletionFence(tx *sql.Tx, item ControlInboxItem, deletionID string) (bool, error) {
	ids := []string{item.OperationID, deletionID, item.MessageID}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		var status string
		err := tx.QueryRow(`SELECT status FROM forward_deletion_operations WHERE id = ?`, id).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("store: check pending deletion fence: %w", err)
		}
		if status != "COMPLETED" {
			return true, nil
		}
	}
	return false, nil
}

func controlInboxLiveProbeFenceByID(tx *sql.Tx, probeID string) (bool, error) {
	var live int
	if err := tx.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM probe_operations o
		 LEFT JOIN probe_terminal_deliveries d ON d.probe_id = o.id
		 WHERE o.id = ? AND (
			o.status IN ('PENDING', 'ARMED', 'IN_FLIGHT')
			OR (d.probe_id IS NOT NULL AND d.disposition NOT IN ('DELIVERED', 'STALE', 'MISSING', 'EXPIRED'))
		 )
	)`, probeID).Scan(&live); err != nil {
		return false, fmt.Errorf("store: check probe inbox replay fence: %w", err)
	}
	return live != 0, nil
}

func controlInboxLiveProbeReceiptFence(tx *sql.Tx, item ControlInboxItem) (bool, error) {
	payload := []byte(item.SemanticPayload)
	if len(payload) < 4+32 || string(payload[:4]) != "RCT1" {
		return true, nil
	}
	var want [32]byte
	copy(want[:], payload[4:4+32])
	// Probe operations are capped by the manager's active budget. Include one
	// extra row so a full bounded page fails closed instead of silently dropping
	// a receipt fence that may be just beyond the page.
	const pageLimit = maxControlInboxCleanupBatch + 1
	rows, err := tx.Query(`SELECT o.arm_hex
		FROM probe_operations o
		LEFT JOIN probe_terminal_deliveries d ON d.probe_id = o.id
		WHERE o.node_id = ? AND (
			o.status IN ('PENDING', 'ARMED', 'IN_FLIGHT')
			OR (d.probe_id IS NOT NULL AND d.disposition NOT IN ('DELIVERED', 'STALE', 'MISSING', 'EXPIRED'))
		)
		ORDER BY o.updated_at, o.id LIMIT ?`, item.NodeID, pageLimit)
	if err != nil {
		return false, fmt.Errorf("store: list live probe receipt fences: %w", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var armHex string
		if err := rows.Scan(&armHex); err != nil {
			return false, fmt.Errorf("store: scan live probe receipt fence: %w", err)
		}
		seen++
		armBytes, err := hex.DecodeString(armHex)
		if err != nil {
			continue
		}
		digest, err := ParseProbeArmLite(armBytes)
		if err == nil && digest == want {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("store: read live probe receipt fences: %w", err)
	}
	if seen == pageLimit {
		return true, nil
	}
	return false, nil
}

// ClaimControlOutboxOperation claims ONE pending row for a session (used when
// a result arrives before the pump re-claimed a requeued row on reconnect).
func (s *Store) ClaimControlOutboxOperation(operationID, messageType, sessionID string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox SET state = 'CLAIMED', session_id = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = 'PENDING'`,
		sessionID, now(), operationID, messageType,
	)
	if err != nil {
		return fmt.Errorf("store: claim outbox operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: claim outbox operation rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: operation %q is not PENDING", ErrIllegalPhase, operationID)
	}
	return nil
}

// ListControlOutboxByState returns the node's outbox rows in the given
// states (used to correlate inbound results/receipts to in-flight rows).
func (s *Store) ListControlOutboxByState(nodeID string, states ...string) ([]ControlOutboxItem, error) {
	return s.ListControlOutboxByStateLimit(nodeID, 256, states...)
}

// ListControlOutboxByStateLimit bounds correlation scans to the active
// outbox budget. Controller history is not a correlation index.
func (s *Store) ListControlOutboxByStateLimit(nodeID string, limit int, states ...string) ([]ControlOutboxItem, error) {
	if len(states) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 256
	}
	placeholders := strings.Repeat("?,", len(states))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(states)+2)
	args = append(args, nodeID)
	for _, st := range states {
		args = append(args, st)
	}
	args = append(args, limit)
	rows, err := s.db.Query(
		`SELECT operation_id, message_type, node_id, semantic_payload, state
		   FROM control_outbox WHERE node_id = ? AND state IN (`+placeholders+`)
		   ORDER BY operation_id LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list control outbox: %w", err)
	}
	defer rows.Close()
	var items []ControlOutboxItem
	for rows.Next() {
		var item ControlOutboxItem
		if err := rows.Scan(&item.OperationID, &item.MessageType, &item.NodeID,
			&item.SemanticPayload, &item.State); err != nil {
			return nil, fmt.Errorf("store: scan control outbox: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// SetNodeControlState updates the node's control_state (ONLINE/OFFLINE).
func (s *Store) SetNodeControlState(nodeID, state string) error {
	res, err := s.db.Exec(
		`UPDATE nodes SET control_state = ?, updated_at = ? WHERE id = ?`,
		state, now(), nodeID,
	)
	if err != nil {
		return fmt.Errorf("store: set node control state: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set node control state rows: %w", err)
	} else if n != 1 {
		return ErrNodeNotFound
	}
	return nil
}
