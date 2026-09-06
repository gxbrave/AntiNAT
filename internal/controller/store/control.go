package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	// ErrStaleControlOwner rejects a live mutation from a session whose
	// epoch/session tuple is no longer the node's durable current owner.
	ErrStaleControlOwner = errors.New("store: control mutation from stale durable owner")
	// ErrMessageConflict rejects a duplicate message_id with different node,
	// operation, type, or payload (fail-closed session conflict, protocol.md §3.5).
	ErrMessageConflict = errors.New("store: control inbox message id conflict")
)

// Control-inbox states are transport dispositions, not a second copy of the
// Agent's generic operation journal. The Agent journal records
// RECEIVED -> INTENT_PERSISTED -> APPLYING -> APPLIED|NACKED. The Controller
// transport inbox records the already-persisted envelope as RECEIVED and then
// projects successful downstream sink completion as PROCESSED (the transport
// equivalent of APPLIED); permanent authenticated input rejection is NACKED.
// Keeping this mapping explicit prevents PROCESSED from being mistaken for a
// new generic FSM state or for the probe-operation outcome REJECTED.
const (
	ControlInboxReceived  = "RECEIVED"
	ControlInboxProcessed = "PROCESSED"
	ControlInboxNacked    = "NACKED"
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
	UpdatedAt       int64
}

// deniedOutboxRowBackoffSeconds is the bounded backoff a delivery-refused
// outbox row waits before the pump may re-claim it (repair-2 L-B). Without it a
// persistently-refused row (cleanup-only node, RESTORE_RECONCILIATION,
// per-node quarantine) would be PENDING->CLAIMED->PENDING on EVERY pump tick.
const deniedOutboxRowBackoffSeconds = int64(30)

// ClaimControlOutbox atomically advances up to limit PENDING rows for a node
// to CLAIMED bound to the session and returns the claimed items in id order.
// This compatibility form retains the historical session-only fixture API;
// live Hub code uses ClaimControlOutboxOwned below.
func (s *Store) ClaimControlOutbox(nodeID, sessionID string, limit int) ([]ControlOutboxItem, error) {
	return s.claimControlOutbox(nodeID, ControlOwner{NodeID: nodeID, SessionID: sessionID}, limit, false)
}

// ClaimControlOutboxOwned claims pending rows only while owner is the node's
// current durable epoch/session owner. The owner predicate is present in both
// selection and update so takeover cannot race a claim.
func (s *Store) ClaimControlOutboxOwned(owner ControlOwner, limit int) ([]ControlOutboxItem, error) {
	return s.claimControlOutbox(owner.NodeID, owner, limit, true)
}

func (s *Store) claimControlOutbox(nodeID string, owner ControlOwner, limit int, fenced bool) ([]ControlOutboxItem, error) {
	if fenced {
		if err := s.validateOwner(owner); err != nil {
			return nil, err
		}
	}
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

	// retry_after_unix gates a delivery-refused row out of the claim set until
	// its bounded backoff expires (repair-2 L-B): the pump must not re-claim
	// the same refused row on every tick.
	query := `SELECT id, operation_id, message_type, node_id, semantic_payload, state, retry_after_unix
		   FROM control_outbox
		  WHERE node_id = ? AND state = 'PENDING' AND retry_after_unix <= ?`
	args := []any{nodeID, s.currentUnix()}
	if fenced {
		query += ` AND EXISTS (SELECT 1 FROM nodes
			 WHERE nodes.id = control_outbox.node_id
			   AND nodes.current_connection_epoch = ?
			   AND nodes.current_session_id = ?)`
		args = append(args, owner.ConnectionEpoch, owner.SessionID)
	}
	query += ` ORDER BY id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := conn.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query pending outbox: %w", err)
	}
	var items []ControlOutboxItem
	var ids []int64
	for rows.Next() {
		var item ControlOutboxItem
		var id int64
		if err := rows.Scan(&id, &item.OperationID, &item.MessageType, &item.NodeID,
			&item.SemanticPayload, &item.State, &item.RetryAfterUnix); err != nil {
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
		query := `UPDATE control_outbox SET state = 'CLAIMED', session_id = ?, updated_at = ?
			  WHERE id = ? AND state = 'PENDING'`
		args := []any{owner.SessionID, now(), id}
		if fenced {
			query += ` AND EXISTS (SELECT 1 FROM nodes
				 WHERE nodes.id = control_outbox.node_id
				   AND nodes.current_connection_epoch = ?
				   AND nodes.current_session_id = ?)`
			args = append(args, owner.ConnectionEpoch, owner.SessionID)
		}
		res, err := conn.ExecContext(context.Background(), query, args...)
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
// by (operation_id, message_type), verifying both the row session binding and
// the node's current durable ControlOwner. The owner predicate is repeated in
// the mutation so a takeover cannot race a prior frame-time check.
func (s *Store) outboxTransitionOwned(operationID, messageType string, owner ControlOwner, want, next string) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE control_outbox
		    SET state = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = ? AND session_id = ?
		    AND EXISTS (SELECT 1 FROM nodes
		                 WHERE nodes.id = control_outbox.node_id
		                   AND nodes.current_connection_epoch = ?
		                   AND nodes.current_session_id = ?)`,
		next, now(), operationID, messageType, want, owner.SessionID,
		owner.ConnectionEpoch, owner.SessionID,
	)
	if err != nil {
		return fmt.Errorf("store: outbox transition %s->%s: %w", want, next, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: outbox transition rows: %w", err)
	}
	if n == 0 {
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
		if session != owner.SessionID {
			return fmt.Errorf("%w: operation %q bound to session %q", ErrStaleSession, operationID, session)
		}
		return fmt.Errorf("%w: operation %q is not %s or owner is stale", ErrStaleControlOwner, operationID, want)
	}
	return nil
}

func (s *Store) outboxTransitionLegacy(operationID, messageType, sessionID, want, next string) error {
	res, err := s.db.Exec(
		`UPDATE control_outbox SET state = ?, updated_at = ?
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
		var session string
		err := s.db.QueryRow(`SELECT session_id FROM control_outbox WHERE operation_id = ? AND message_type = ?`, operationID, messageType).Scan(&session)
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
	return s.outboxTransitionLegacy(operationID, messageType, sessionID, "CLAIMED", "SENT")
}

// MarkControlOutboxSentOwned advances CLAIMED -> SENT and fences the mutation
// to the supplied durable node owner.
func (s *Store) MarkControlOutboxSentOwned(operationID, messageType string, owner ControlOwner) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	return s.outboxTransitionOwned(operationID, messageType, owner, "CLAIMED", "SENT")
}

// AcceptControlSemanticACK advances SENT -> SEMANTIC_ACKED. A semantic ACK
// never permits GC.
func (s *Store) AcceptControlSemanticACK(operationID, messageType, sessionID string) error {
	return s.outboxTransitionLegacy(operationID, messageType, sessionID, "SENT", "SEMANTIC_ACKED")
}

// AcceptControlSemanticACKOwned advances SENT -> SEMANTIC_ACKED under the
// current durable node owner.
func (s *Store) AcceptControlSemanticACKOwned(operationID, messageType string, owner ControlOwner) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	return s.outboxTransitionOwned(operationID, messageType, owner, "SENT", "SEMANTIC_ACKED")
}

// AcceptControlReceipt advances SEMANTIC_ACKED -> RECEIPTED and GCs the row
// (the durable receipt is recorded in control_inbox; the outbox row is
// deleted so the outbox stays bounded). This compatibility form intentionally
// remains ownerless for recovery and historical fixture callers.
func (s *Store) AcceptControlReceipt(operationID, messageType, sessionID string) error {
	return s.acceptControlReceipt("", "", "", operationID, messageType, sessionID, nil)
}

// AcceptControlReceiptWithInbox consumes a correlated message_receipt and
// projects its durable inbox row to PROCESSED in the same SQLite transaction
// as SEMANTIC_ACKED -> RECEIPTED -> GC. This compatibility form is retained
// for recovery/admin callers; live sessions use the owner-fenced variant.
func (s *Store) AcceptControlReceiptWithInbox(messageID, operationID, messageType, sessionID string) error {
	if messageID == "" {
		return errors.New("store: receipt inbox message id is required")
	}
	return s.acceptControlReceipt(messageID, "", "", operationID, messageType, sessionID, nil)
}

// AcceptControlReceiptOwned consumes a receipt under the complete durable
// owner tuple. It is the owner-fenced equivalent of AcceptControlReceipt for
// callers that do not have an inbox message id.
func (s *Store) AcceptControlReceiptOwned(owner ControlOwner, operationID, messageType string) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	return s.acceptControlReceipt("", "", "", operationID, messageType, owner.SessionID, &owner)
}

// ControlReceipt identifies one authenticated Agent receipt and the durable
// Controller outbox row it acknowledges. The inbox and outbox operation ids are
// intentionally separate: an Agent result is journaled under the hex command
// message id, while the Controller row is keyed by its semantic operation id.
// InboxOperationID and SemanticPayload are assertions over the exact durable
// inbox row; neither selects the Controller outbox row.
type ControlReceipt struct {
	ReceiptMessageID  string
	SemanticPayload   string
	InboxOperationID  string
	OutboxOperationID string
	OutboxMessageType string
}

// AcceptControlReceiptWithInboxOwned atomically projects the live-session
// receipt inbox row and consumes the correlated controller outbox row. This
// compatibility form retains the historical argument shape; callers that have
// the exact authenticated payload should use AcceptControlReceiptOwnedInbox.
func (s *Store) AcceptControlReceiptWithInboxOwned(owner ControlOwner, messageID, operationID, messageType string) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	if messageID == "" {
		return errors.New("store: receipt inbox message id is required")
	}
	return s.acceptControlReceipt(messageID, "", "", operationID, messageType, owner.SessionID, &owner)
}

// AcceptControlReceiptOwnedInbox is the owner-fenced receipt API for live
// sessions. It validates the exact authenticated receipt inbox material while
// keeping its Agent-side operation binding distinct from the Controller
// outbox operation selected by durable correlation.
func (s *Store) AcceptControlReceiptOwnedInbox(owner ControlOwner, receipt ControlReceipt) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	if receipt.ReceiptMessageID == "" || receipt.OutboxOperationID == "" || receipt.OutboxMessageType == "" {
		return errors.New("store: receipt identity is incomplete")
	}
	return s.acceptControlReceipt(
		receipt.ReceiptMessageID,
		receipt.InboxOperationID,
		receipt.SemanticPayload,
		receipt.OutboxOperationID,
		receipt.OutboxMessageType,
		owner.SessionID,
		&owner,
	)
}

func (s *Store) acceptControlReceipt(inboxMessageID, inboxOperationID, inboxPayload, operationID, messageType, sessionID string, owner *ControlOwner) error {
	// This path reads the outbox and related fan-in rows before deleting the
	// receipt. A deferred transaction can read a WAL snapshot and later fail
	// with SQLITE_BUSY_SNAPSHOT when it upgrades that stale snapshot. Reserve
	// the write lock before the first read, as ClaimControlOutbox and probe
	// joins do, so transient writer contention waits instead of tearing down
	// the AgentHub session.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("store: outbox receipt conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin outbox receipt: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	outboxQuery := `SELECT state, session_id, node_id FROM control_outbox
		WHERE operation_id = ? AND message_type = ?`
	outboxArgs := []any{operationID, messageType}
	if owner != nil {
		outboxQuery += ` AND node_id = ? AND EXISTS (SELECT 1 FROM nodes
			WHERE nodes.id = control_outbox.node_id
			  AND nodes.current_connection_epoch = ?
			  AND nodes.current_session_id = ?)`
		outboxArgs = append(outboxArgs, owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
	}
	var state, session, nodeID string
	err = conn.QueryRowContext(context.Background(), outboxQuery, outboxArgs...).Scan(&state, &session, &nodeID)
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
	markReceiptInbox := func() error {
		if inboxMessageID == "" {
			return nil
		}
		query := `UPDATE control_inbox SET state = 'PROCESSED', updated_at = ?
			WHERE message_id = ? AND state = 'RECEIVED'`
		args := []any{now(), inboxMessageID}
		if owner != nil {
			query += ` AND node_id = ?
				AND (operation_id IS NULL OR operation_id = '' OR operation_id = ?)
				AND EXISTS (SELECT 1 FROM nodes
				 WHERE nodes.id = control_inbox.node_id
				   AND nodes.current_connection_epoch = ?
				   AND nodes.current_session_id = ?)`
			args = append(args, owner.NodeID, inboxOperationID, owner.ConnectionEpoch, owner.SessionID)
		}
		res, err := conn.ExecContext(context.Background(), query, args...)
		if err != nil {
			return fmt.Errorf("store: mark receipt inbox processed: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: mark receipt inbox processed rows: %w", err)
		}
		if n == 1 {
			return nil
		}
		var inboxNode, inboxState, inboxOperation string
		if err := conn.QueryRowContext(context.Background(),
			`SELECT node_id, state, COALESCE(operation_id, '') FROM control_inbox WHERE message_id = ?`, inboxMessageID,
		).Scan(&inboxNode, &inboxState, &inboxOperation); err != nil {
			return fmt.Errorf("store: recheck receipt inbox state: %w", err)
		}
		if owner != nil && inboxNode != owner.NodeID {
			return fmt.Errorf("%w: receipt inbox belongs to node %q", ErrMessageConflict, inboxNode)
		}
		if owner != nil && inboxOperation != "" && inboxOperation != inboxOperationID {
			return fmt.Errorf("%w: receipt inbox operation binding differs", ErrMessageConflict)
		}
		if inboxState == ControlInboxProcessed {
			return nil
		}
		return fmt.Errorf("%w: receipt inbox is %s, want RECEIVED", ErrIllegalPhase, inboxState)
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
		if err := conn.QueryRowContext(
			context.Background(),
			`SELECT COUNT(*) FROM forward_deletion_operations WHERE id = ?`, operationID,
		).Scan(&deletionCount); err != nil {
			return fmt.Errorf("store: check deletion result fan-in: %w", err)
		}
		if deletionCount == 1 {
			var commandResultID, controllerResultID string
			if err := conn.QueryRowContext(context.Background(), `
				SELECT operation_complete_message_id, controller_operation_complete_message_id
				  FROM control_outbox
				 WHERE operation_id = ? AND message_type = ?`, operationID, messageType,
			).Scan(&commandResultID, &controllerResultID); err != nil {
				return fmt.Errorf("store: read deletion result fan-in ids: %w", err)
			}
			var resultCount int
			if err := conn.QueryRowContext(context.Background(), `
				SELECT COUNT(*) FROM control_inbox
				 WHERE node_id = ? AND message_id IN (?, ?)`,
				nodeID, commandResultID, controllerResultID,
			).Scan(&resultCount); err != nil {
				return fmt.Errorf("store: check deletion result fan-in rows: %w", err)
			}
			if resultCount < 2 {
				// The receipt itself is a durable inbound message. Project it to
				// PROCESSED before retaining the fan-in outbox row, and commit
				// both facts together so a crash cannot leave a successful
				// receipt row looking retryable.
				if err := markReceiptInbox(); err != nil {
					return err
				}
				if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
					return fmt.Errorf("store: commit retained deletion outbox: %w", err)
				}
				committed = true
				return nil
			}
		}
	}
	if err := markReceiptInbox(); err != nil {
		return err
	}
	transitionQuery := `UPDATE control_outbox SET state = 'RECEIPTED', updated_at = ?
		WHERE operation_id = ? AND message_type = ? AND state = 'SEMANTIC_ACKED' AND session_id = ?`
	transitionArgs := []any{now(), operationID, messageType, sessionID}
	if owner != nil {
		transitionQuery += ` AND node_id = ? AND EXISTS (SELECT 1 FROM nodes
			WHERE nodes.id = control_outbox.node_id
			  AND nodes.current_connection_epoch = ?
			  AND nodes.current_session_id = ?)`
		transitionArgs = append(transitionArgs, owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
	}
	res, err := conn.ExecContext(context.Background(), transitionQuery, transitionArgs...)
	if err != nil {
		return fmt.Errorf("store: mark outbox receipted: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: mark outbox receipted rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: operation %q could not enter RECEIPTED", ErrIllegalPhase, operationID)
	}
	// A terminal probe outcome needs a durable acknowledgement fence that
	// survives outbox GC. Keep it in the operation's evidence rows so the
	// marker is removed atomically with the terminal tombstone, while a crash
	// between receipt processing and recovery cannot cause a duplicate command.
	if messageType == "probe_outcome" {
		markerQuery := `INSERT OR IGNORE INTO probe_results (probe_id, kind, payload_hex, created_at)
			SELECT ?, 'outcome_acked', 'ack', ?
			WHERE EXISTS (SELECT 1 FROM control_outbox WHERE operation_id = ? AND message_type = ? AND node_id = ?)`
		markerArgs := []any{operationID, now(), operationID, messageType, nodeID}
		if owner != nil {
			markerQuery += ` AND EXISTS (SELECT 1 FROM nodes
				WHERE nodes.id = ? AND nodes.current_connection_epoch = ? AND nodes.current_session_id = ?)`
			markerArgs = append(markerArgs, owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
		}
		if _, err := conn.ExecContext(context.Background(), markerQuery, markerArgs...); err != nil {
			return fmt.Errorf("store: record probe outcome acknowledgement: %w", err)
		}
		terminalQuery := `UPDATE probe_terminal_deliveries SET disposition = 'DELIVERED', updated_at = ?
			WHERE probe_id = ? AND node_id = ? AND disposition = 'ENQUEUED'`
		terminalArgs := []any{now(), operationID, nodeID}
		if owner != nil {
			terminalQuery += ` AND EXISTS (SELECT 1 FROM nodes
				WHERE nodes.id = ? AND nodes.current_connection_epoch = ? AND nodes.current_session_id = ?)`
			terminalArgs = append(terminalArgs, owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
		}
		res, err := conn.ExecContext(context.Background(), terminalQuery, terminalArgs...)
		if err != nil {
			return fmt.Errorf("store: mark probe outcome delivered: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("store: mark probe outcome delivered rows: %w", err)
		} else if n != 1 {
			return fmt.Errorf("%w: probe outcome %q delivery is not ENQUEUED", ErrIllegalPhase, operationID)
		}
	}
	// The receipt inbox projection was performed before the outbox transition so
	// both records commit atomically. Keep this point free of a second update.
	// GC: the outbox row is removed; the durable record lives in control_inbox.
	deleteQuery := `DELETE FROM control_outbox
		WHERE operation_id = ? AND message_type = ? AND state = 'RECEIPTED' AND session_id = ?`
	deleteArgs := []any{operationID, messageType, sessionID}
	if owner != nil {
		deleteQuery += ` AND node_id = ? AND EXISTS (SELECT 1 FROM nodes
			WHERE nodes.id = control_outbox.node_id
			  AND nodes.current_connection_epoch = ?
			  AND nodes.current_session_id = ?)`
		deleteArgs = append(deleteArgs, owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
	}
	res, err = conn.ExecContext(context.Background(), deleteQuery, deleteArgs...)
	if err != nil {
		return fmt.Errorf("store: gc outbox row: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: gc outbox rows: %w", err)
	} else if n != 1 {
		return fmt.Errorf("%w: operation %q receipt GC did not remove one row", ErrIllegalPhase, operationID)
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return fmt.Errorf("store: commit outbox receipt: %w", err)
	}
	committed = true
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

// RequeueControlOutboxForOwner resets in-flight rows only for the current
// durable owner. A stale teardown cannot requeue rows that a newer session has
// already taken over.
func (s *Store) RequeueControlOutboxForOwner(owner ControlOwner) (int, error) {
	if err := s.validateOwner(owner); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`UPDATE control_outbox
		SET state = 'PENDING', session_id = ?, updated_at = ?
		WHERE node_id = ? AND state IN ('CLAIMED', 'SENT')
		  AND EXISTS (SELECT 1 FROM nodes
			 WHERE nodes.id = control_outbox.node_id
			   AND nodes.current_connection_epoch = ?
			   AND nodes.current_session_id = ?)`,
		owner.SessionID, now(), owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
	if err != nil {
		return 0, fmt.Errorf("store: requeue owned outbox: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: requeue owned outbox rows: %w", err)
	}
	return int(n), nil
}

// RequeueControlOutboxItemOwned resets a SINGLE in-flight (CLAIMED/SENT) row to
// PENDING while the caller remains the node's durable owner, and schedules a
// bounded backoff so the pump does not re-claim it on every tick (repair-2
// L-B). The outbox pump uses it when a delivery-time quarantine/tombstone gate
// refuses a forbidden row (repair-1 L4/H2c): the row is kept owned and retryable
// (retry_after_unix now + deniedOutboxRowBackoffSeconds) instead of stranded in
// CLAIMED forever, so a later reauthorization can deliver it without a hot
// PENDING→CLAIMED cycle in the meantime.
func (s *Store) RequeueControlOutboxItemOwned(operationID, messageType string, owner ControlOwner) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE control_outbox
		SET state = 'PENDING', session_id = ?, updated_at = ?, retry_after_unix = ?
		WHERE operation_id = ? AND message_type = ? AND state IN ('CLAIMED', 'SENT')
		  AND EXISTS (SELECT 1 FROM nodes
			 WHERE nodes.id = control_outbox.node_id
			   AND nodes.current_connection_epoch = ?
			   AND nodes.current_session_id = ?)`,
		owner.SessionID, now(), now()+deniedOutboxRowBackoffSeconds, operationID, messageType,
		owner.ConnectionEpoch, owner.SessionID)
	if err != nil {
		return fmt.Errorf("store: requeue owned outbox item: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: requeue owned outbox item rows: %w", err)
	} else if n == 0 {
		// Already PENDING (or the rollback of the same row), or we lost the
		// durable owner. A stale requeue must not strand the row.
		return s.RequireCurrentControlOwner(owner)
	}
	return nil
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

// RebindControlOutboxSessionOwned rebinds a semantic result only while the
// caller remains the node's durable owner. A stale result replay cannot steal a
// row from a newer session or authorize a later receipt.
func (s *Store) RebindControlOutboxSessionOwned(operationID, messageType string, owner ControlOwner) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE control_outbox
		SET session_id = ?, updated_at = ?
		WHERE operation_id = ? AND message_type = ? AND state = 'SEMANTIC_ACKED'
		  AND EXISTS (SELECT 1 FROM nodes
			 WHERE nodes.id = control_outbox.node_id
			   AND nodes.current_connection_epoch = ?
			   AND nodes.current_session_id = ?)`,
		owner.SessionID, now(), operationID, messageType,
		owner.ConnectionEpoch, owner.SessionID)
	if err != nil {
		return fmt.Errorf("store: rebind owned outbox session: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: rebind owned outbox rows: %w", err)
	} else if n == 1 {
		return nil
	}
	if err := s.RequireCurrentControlOwner(owner); err != nil {
		return err
	}
	var state, session string
	if err := s.db.QueryRow(`SELECT state, COALESCE(session_id, '')
		FROM control_outbox WHERE operation_id = ? AND message_type = ?`,
		operationID, messageType).Scan(&state, &session); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q has no outbox row", ErrIllegalPhase, operationID)
	} else if err != nil {
		return err
	}
	if state != "SEMANTIC_ACKED" {
		return fmt.Errorf("%w: operation %q is %s, want SEMANTIC_ACKED", ErrIllegalPhase, operationID, state)
	}
	if session == owner.SessionID {
		return nil
	}
	return fmt.Errorf("%w: operation %q is bound to session %q", ErrStaleSession, operationID, session)
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

// withControlOwnerImmediate runs one owner-fenced control-inbox mutation in a
// write transaction. The durable owner is checked after BEGIN IMMEDIATE and
// every caller's mutation repeats the same owner predicate in SQL. Reserving
// the write lock before the check prevents a takeover from committing between
// the check and the mutation, while the predicate keeps the fence explicit at
// the write boundary.
func (s *Store) withControlOwnerImmediate(owner ControlOwner, fn func(*sql.Conn) error) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return errStoreClosed
	}

	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: control owner conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin owned control transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var matched int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM nodes
		 WHERE id = ? AND current_connection_epoch = ? AND current_session_id = ?
	)`, owner.NodeID, owner.ConnectionEpoch, owner.SessionID).Scan(&matched); err != nil {
		return fmt.Errorf("store: check owned control transaction: %w", err)
	}
	if matched != 1 {
		return fmt.Errorf("%w: node %q owner is no longer current", ErrStaleControlOwner, owner.NodeID)
	}
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit owned control transaction: %w", err)
	}
	committed = true
	return nil
}

// RecordControlInboxOwned durably records an inbound message only while owner
// remains the node's current durable ControlOwner. The insert and duplicate
// comparison share one BEGIN IMMEDIATE transaction, so cleanup cannot remove
// the row between INSERT OR IGNORE and the duplicate read.
func (s *Store) RecordControlInboxOwned(owner ControlOwner, item ControlInboxItem) (bool, error) {
	if err := s.validateOwner(owner); err != nil {
		return false, err
	}
	if item.NodeID != owner.NodeID {
		return false, fmt.Errorf("%w: inbox node %q does not match owner node %q", ErrMessageConflict, item.NodeID, owner.NodeID)
	}
	timestamp := s.currentUnix()
	duplicate := false
	err := s.withControlOwnerImmediate(owner, func(conn *sql.Conn) error {
		// INSERT ... SELECT gives the mutation itself the full durable-owner
		// predicate; the transaction-level check above makes a takeover unable to
		// commit until this transaction has finished.
		res, err := conn.ExecContext(context.Background(),
			`INSERT OR IGNORE INTO control_inbox
			    (message_id, node_id, message_type, semantic_payload, state,
			     operation_id, created_at, updated_at)
			 SELECT ?, ?, ?, ?, 'RECEIVED', ?, ?, ?
			  WHERE EXISTS (SELECT 1 FROM nodes
			                 WHERE nodes.id = ?
			                   AND nodes.current_connection_epoch = ?
			                   AND nodes.current_session_id = ?)`,
			item.MessageID, item.NodeID, item.MessageType, item.SemanticPayload,
			item.OperationID, timestamp, timestamp,
			owner.NodeID, owner.ConnectionEpoch, owner.SessionID,
		)
		if err != nil {
			return fmt.Errorf("store: record owned control inbox: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: record owned control inbox rows: %w", err)
		}
		if n == 1 {
			return nil
		}

		var existingNodeID, existingMessageType, existingOperationID, existingPayload string
		err = conn.QueryRowContext(context.Background(),
			`SELECT node_id, message_type, COALESCE(operation_id, ''), semantic_payload
			   FROM control_inbox WHERE message_id = ?`, item.MessageID,
		).Scan(&existingNodeID, &existingMessageType, &existingOperationID, &existingPayload)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: owned control inbox row disappeared after duplicate insert")
		}
		if err != nil {
			return fmt.Errorf("store: get owned control inbox: %w", err)
		}
		if existingNodeID != item.NodeID || existingMessageType != item.MessageType ||
			existingOperationID != item.OperationID || existingPayload != item.SemanticPayload {
			return fmt.Errorf("%w: message %q binding/material differs from persisted row", ErrMessageConflict, item.MessageID)
		}
		duplicate = true
		return nil
	})
	return duplicate, err
}

// BindControlInboxOperationIDOwned fills a legacy empty operation binding only
// while owner is current. The exact-match fallback is performed on the same
// transaction/connection as the conditional update.
func (s *Store) BindControlInboxOperationIDOwned(owner ControlOwner, messageID, operationID string) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	if messageID == "" || operationID == "" {
		return ErrCASConflict
	}
	return s.withControlOwnerImmediate(owner, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(context.Background(),
			`UPDATE control_inbox SET operation_id = ?, updated_at = ?
			  WHERE message_id = ? AND node_id = ?
			    AND (operation_id IS NULL OR operation_id = '')
			    AND EXISTS (SELECT 1 FROM nodes
			                 WHERE nodes.id = control_inbox.node_id
			                   AND nodes.current_connection_epoch = ?
			                   AND nodes.current_session_id = ?)`,
			operationID, s.currentUnix(), messageID, owner.NodeID,
			owner.ConnectionEpoch, owner.SessionID,
		)
		if err != nil {
			return fmt.Errorf("store: bind owned inbox operation: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: bind owned inbox operation rows: %w", err)
		}
		if n == 1 {
			return nil
		}

		var existingNodeID, existingOperationID string
		err = conn.QueryRowContext(context.Background(),
			`SELECT node_id, COALESCE(operation_id, '')
			   FROM control_inbox WHERE message_id = ?`, messageID,
		).Scan(&existingNodeID, &existingOperationID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: get owned inbox operation: %w", err)
		}
		if existingNodeID != owner.NodeID {
			return fmt.Errorf("%w: inbox message %q belongs to node %q", ErrMessageConflict, messageID, existingNodeID)
		}
		if existingOperationID == operationID {
			return nil
		}
		return fmt.Errorf("%w: inbox message %q operation binding differs", ErrMessageConflict, messageID)
	})
}

// SetControlInboxStateOwned records completion of a durable inbound message
// only while owner is current. The transport projection remains strict:
// RECEIVED may become PROCESSED or NACKED, and repeating the same terminal
// disposition is idempotent.
func (s *Store) SetControlInboxStateOwned(owner ControlOwner, messageID, state string) error {
	if messageID == "" || state == "" {
		return errors.New("store: control inbox state requires message id and state")
	}
	if state != ControlInboxProcessed && state != ControlInboxNacked {
		return fmt.Errorf("%w: control inbox cannot enter state %q", ErrIllegalPhase, state)
	}
	return s.setControlInboxStateOwned(owner, messageID, state)
}

// RejectControlInboxOwned terminalizes an authenticated inbox message as
// NACKED only while owner is current. It is intended for permanent input
// rejection; retryable failures must leave RECEIVED.
func (s *Store) RejectControlInboxOwned(owner ControlOwner, messageID string) error {
	if messageID == "" {
		return errors.New("store: control inbox rejection requires message id")
	}
	return s.setControlInboxStateOwned(owner, messageID, ControlInboxNacked)
}

func (s *Store) setControlInboxStateOwned(owner ControlOwner, messageID, state string) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	return s.withControlOwnerImmediate(owner, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(context.Background(),
			`UPDATE control_inbox SET state = ?, updated_at = ?
			  WHERE message_id = ? AND node_id = ? AND state = 'RECEIVED'
			    AND EXISTS (SELECT 1 FROM nodes
			                 WHERE nodes.id = control_inbox.node_id
			                   AND nodes.current_connection_epoch = ?
			                   AND nodes.current_session_id = ?)`,
			state, s.currentUnix(), messageID, owner.NodeID,
			owner.ConnectionEpoch, owner.SessionID,
		)
		if err != nil {
			return fmt.Errorf("store: set owned control inbox state: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: set owned control inbox state rows: %w", err)
		}
		if n == 1 {
			return nil
		}

		var existingNodeID, current string
		err = conn.QueryRowContext(context.Background(),
			`SELECT node_id, state FROM control_inbox WHERE message_id = ?`, messageID,
		).Scan(&existingNodeID, &current)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: get owned control inbox state: %w", err)
		}
		if existingNodeID != owner.NodeID {
			return fmt.Errorf("%w: inbox message %q belongs to node %q", ErrMessageConflict, messageID, existingNodeID)
		}
		if current == state {
			return nil
		}
		return fmt.Errorf("%w: control inbox message %q is %s, want RECEIVED", ErrIllegalPhase, messageID, current)
	})
}

// SetControlInboxState records completion of a durable inbound message's
// downstream handling. The transport projection is strict: only RECEIVED may
// become PROCESSED or NACKED. Replays of an already terminal disposition are
// idempotent, while all other transitions fail closed. A sink failure leaves
// RECEIVED so deterministic redelivery can retry it.
func (s *Store) SetControlInboxState(messageID, state string) error {
	if messageID == "" || state == "" {
		return errors.New("store: control inbox state requires message id and state")
	}
	if state != ControlInboxProcessed && state != ControlInboxNacked {
		return fmt.Errorf("%w: control inbox cannot enter state %q", ErrIllegalPhase, state)
	}
	res, err := s.db.Exec(
		`UPDATE control_inbox SET state = ?, updated_at = ?
		  WHERE message_id = ? AND state = 'RECEIVED'`,
		state, s.currentUnix(), messageID,
	)
	if err != nil {
		return fmt.Errorf("store: set control inbox state: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set control inbox state rows: %w", err)
	} else if n == 1 {
		return nil
	}
	current, err := s.ControlInboxState(messageID)
	if err != nil {
		return err
	}
	if current == state {
		return nil
	}
	return fmt.Errorf("%w: control inbox message %q is %s, want RECEIVED", ErrIllegalPhase, messageID, current)
}

// SetControlInboxStateExact completes one already-admitted inbox delivery
// without consulting the current connection owner. The exact authenticated row
// identity is the authorization boundary: a handler that entered the sink before
// a takeover must be able to publish the sink result, while a stale handler
// cannot complete a different node/type/payload. This is intentionally separate
// from owner-fenced admission and owner-sensitive mutations.
func (s *Store) SetControlInboxStateExact(item ControlInboxItem, state string) error {
	if item.MessageID == "" || item.NodeID == "" || item.MessageType == "" || state == "" {
		return errors.New("store: exact control inbox state requires message identity and state")
	}
	if state != ControlInboxProcessed && state != ControlInboxNacked {
		return fmt.Errorf("%w: control inbox cannot enter state %q", ErrIllegalPhase, state)
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("store: exact control inbox conn: %w", err)
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin exact control inbox state: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	query := `UPDATE control_inbox SET state = ?, updated_at = ?
		WHERE message_id = ? AND node_id = ? AND message_type = ?
		  AND semantic_payload = ? AND state = 'RECEIVED'`
	args := []any{state, s.currentUnix(), item.MessageID, item.NodeID,
		item.MessageType, item.SemanticPayload}
	if item.OperationID == "" {
		query += ` AND (operation_id IS NULL OR operation_id = '')`
	} else {
		query += ` AND operation_id = ?`
		args = append(args, item.OperationID)
	}
	res, err := conn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store: set exact control inbox state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set exact control inbox state rows: %w", err)
	}
	if n == 1 {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return fmt.Errorf("store: commit exact control inbox state: %w", err)
		}
		committed = true
		return nil
	}

	var existing ControlInboxItem
	err = conn.QueryRowContext(ctx, `SELECT node_id, message_type,
		semantic_payload, COALESCE(operation_id, ''), state
		FROM control_inbox WHERE message_id = ?`, item.MessageID).Scan(
		&existing.NodeID, &existing.MessageType, &existing.SemanticPayload,
		&existing.OperationID, &existing.State)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: recheck exact control inbox state: %w", err)
	}
	if existing.NodeID != item.NodeID || existing.MessageType != item.MessageType ||
		existing.SemanticPayload != item.SemanticPayload || existing.OperationID != item.OperationID {
		return fmt.Errorf("%w: exact control inbox identity differs", ErrMessageConflict)
	}
	if existing.State != state {
		return fmt.Errorf("%w: control inbox message %q is %s, want RECEIVED", ErrIllegalPhase, item.MessageID, existing.State)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit exact control inbox replay: %w", err)
	}
	committed = true
	return nil
}

// RejectControlInbox terminalizes an authenticated probe receipt that is
// permanently malformed or uncorrelatable. NACKED is the transport projection
// of the frozen APPLYING -> NACKED negative terminal state; the transition is
// one-way from RECEIVED at this layer. An already terminal row is idempotent,
// while transient store errors are returned so the caller can leave the row
// retryable.
func (s *Store) RejectControlInbox(messageID string) error {
	if messageID == "" {
		return errors.New("store: control inbox rejection requires message id")
	}
	res, err := s.db.Exec(
		`UPDATE control_inbox SET state = 'NACKED', updated_at = ?
		  WHERE message_id = ? AND state = 'RECEIVED'`,
		s.currentUnix(), messageID,
	)
	if err != nil {
		return fmt.Errorf("store: reject control inbox: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: reject control inbox rows: %w", err)
	} else if n == 1 {
		return nil
	}
	state, err := s.ControlInboxState(messageID)
	if err != nil {
		return err
	}
	if state == ControlInboxNacked {
		return nil
	}
	return fmt.Errorf("%w: control inbox message %q is %s", ErrIllegalPhase, messageID, state)
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

type controlInboxCleanupCursor struct {
	mu          sync.Mutex
	highWater   int64
	beforeID    int64
	initialized bool
	closed      bool
}

func (c *controlInboxCleanupCursor) resetLocked() {
	c.highWater = 0
	c.beforeID = 0
	c.initialized = false
}

// DeleteControlInboxBeforeLimit reclaims processed control-inbox tombstones
// older than the replay cutoff in bounded, high-water passes. A high-water ID
// is captured before selecting candidates, so rows arriving during cleanup are
// never accidentally consumed by the same pass. Rows that still back a live
// outbox/deletion/probe replay fence are retained even when they are old. Each
// call examines at most maxControlInboxCleanupScan raw IDs and advances a
// descending keyset. Fairness is guaranteed for the lifetime of one Store;
// reopening the database starts a fresh process-local high-water cycle.
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
	if s == nil || s.db == nil {
		return 0, errStoreClosed
	}

	// Serialize cursor ownership for callers sharing one Store. The database
	// transaction remains the atomic high-water/delete boundary; the cursor is
	// advanced only after a successful commit.
	cursor := &s.inboxCleanupCursor
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	if cursor.closed {
		return 0, errStoreClosed
	}

	// Keep all cursor mutations local until the transaction commits. If any
	// query, fence, delete, or commit fails, the next call retries the same
	// boundary rather than skipping rows from a rolled-back transaction.
	highWater := cursor.highWater
	beforeID := cursor.beforeID
	initialized := cursor.initialized

	// A deferred WAL transaction can read a snapshot and then fail with
	// SQLITE_BUSY_SNAPSHOT when cleanup upgrades that snapshot to a writer.
	// Reserve the write lock before the high-water read and every retention
	// lookup so cleanup has one deterministic read/write boundary.
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: control inbox cleanup conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return 0, fmt.Errorf("store: begin control inbox cleanup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	if !initialized {
		if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM control_inbox`).Scan(&highWater); err != nil {
			return 0, fmt.Errorf("store: read control inbox cleanup high-water: %w", err)
		}
		if highWater == 0 {
			if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
				return 0, fmt.Errorf("store: commit empty control inbox cleanup: %w", err)
			}
			committed = true
			return 0, nil
		}
		beforeID = highWater
		initialized = true
	}

	// Scan raw INTEGER PRIMARY KEY order, not a filtered state index. Applying
	// state/cutoff eligibility in Go makes LIMIT a true examined-row budget;
	// NOT INDEXED lets SQLite satisfy the descending rowid keyset without a
	// historical sort or TEMP B-TREE. Protected rows still advance the cursor.
	query := `SELECT id, message_id, node_id, message_type,
		COALESCE(operation_id, ''), semantic_payload, state, updated_at
		FROM control_inbox NOT INDEXED
		WHERE id <= ? AND id > 0
		ORDER BY id DESC LIMIT ?`
	rows, err := conn.QueryContext(ctx, query, beforeID, scanLimit)
	if err != nil {
		return 0, fmt.Errorf("store: select control inbox cleanup scan: %w", err)
	}
	var candidates []ControlInboxItem
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.ID, &item.MessageID, &item.NodeID,
			&item.MessageType, &item.OperationID, &item.SemanticPayload,
			&item.State, &item.UpdatedAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: scan control inbox cleanup row: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("store: close control inbox cleanup scan: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: read control inbox cleanup scan: %w", err)
	}

	removed := 0
	var lastExaminedID int64
	for _, item := range candidates {
		lastExaminedID = item.ID
		if item.State != ControlInboxProcessed && item.State != ControlInboxNacked {
			continue
		}
		if item.UpdatedAt >= cutoff {
			continue
		}
		protected, err := controlInboxRetentionProtected(conn, item)
		if err != nil {
			return 0, err
		}
		if protected {
			continue
		}
		res, err := conn.ExecContext(ctx, `DELETE FROM control_inbox
			WHERE id = ? AND id <= ? AND state IN ('PROCESSED', 'NACKED') AND updated_at < ?`,
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

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, fmt.Errorf("store: commit control inbox cleanup: %w", err)
	}
	committed = true
	if len(candidates) == 0 || lastExaminedID <= 1 {
		// Start a fresh high-water cycle after reaching the oldest row. New
		// rows are then included, while rows above the prior high-water remain
		// excluded from the just-completed pass.
		cursor.resetLocked()
	} else {
		cursor.highWater = highWater
		cursor.beforeID = lastExaminedID - 1
		cursor.initialized = initialized
	}
	return removed, nil
}

// controlSQL is the small common query surface used by cleanup's dedicated
// connection and the older transaction-backed retention helpers.
type controlSQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// controlInboxRetentionProtected keeps a processed tombstone while a later
// reconnect/result path still needs it. All checks run on the cleanup
// transaction so the dependency decision and delete share one SQLite snapshot.
func controlInboxRetentionProtected(tx controlSQL, item ControlInboxItem) (bool, error) {
	if item.State == "NACKED" && item.MessageType == "probe_ingress_receipt" {
		// A rejected probe receipt is a terminal admission tombstone; it has
		// no successful downstream artifact whose replay fence must survive.
		return false, nil
	}
	// Only the durable inbox operation binding and exact message identity may
	// participate in retention. Peer-controlled JSON payload fields are
	// assertions for their operation-specific handlers, never lookup keys.
	outboxFence, err := controlInboxOutboxFence(tx, item.NodeID, item.OperationID, item.MessageID)
	if err != nil {
		return false, err
	}
	if outboxFence {
		return true, nil
	}

	switch item.MessageType {
	case "operation_complete":
		return controlInboxPendingDeletionFence(tx, item)
	case "probe_result":
		if item.OperationID == "" {
			// A processed result without a durable operation discriminator cannot
			// be proven safe to discard; retain it fail-closed.
			return true, nil
		}
		return controlInboxLiveProbeFenceByID(tx, item.OperationID)
	case "probe_ingress_receipt":
		return controlInboxLiveProbeReceiptFence(tx, item)
	default:
		return false, nil
	}
}

// controlInboxOutboxFence protects a tombstone while its exact durable
// operation/message correlation remains resendable. The caller supplies only
// values already bound in trusted storage; no payload-derived identifier is
// accepted here. Empty bindings fail open for ordinary uncorrelated history.
func controlInboxOutboxFence(tx controlSQL, nodeID string, operationID ...string) (bool, error) {
	if len(operationID) == 0 || (operationID[0] == "" && (len(operationID) < 2 || operationID[1] == "")) {
		return false, nil
	}
	var live int
	var err error
	if len(operationID) > 1 && operationID[1] != "" {
		// A durable message_receipt row stores the Agent-side operation
		// identity. For an ordinary result that identity is the command
		// message id, not the Controller semantic operation id; retain the
		// tombstone while either exact durable binding is still live. The
		// second value is the inbox message id and is checked against the
		// indexed result identities. Neither value comes from peer JSON.
		err = tx.QueryRowContext(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM control_outbox o
			 WHERE o.node_id = ? AND (
				o.operation_id = ?
				OR o.command_message_id = ?
				OR o.operation_complete_message_id = ?
				OR o.controller_operation_complete_message_id = ?
			 )
		)`, nodeID, operationID[0], operationID[0], operationID[1], operationID[1]).Scan(&live)
	} else {
		err = tx.QueryRowContext(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM control_outbox o
			 WHERE o.node_id = ? AND (
				o.operation_id = ? OR o.command_message_id = ?
			 )
		)`, nodeID, operationID[0], operationID[0]).Scan(&live)
	}
	if err != nil {
		return false, fmt.Errorf("store: check control inbox outbox fence: %w", err)
	}
	return live != 0, nil
}

func controlInboxPendingDeletionFence(tx controlSQL, item ControlInboxItem) (bool, error) {
	if item.OperationID == "" {
		// Without a trusted operation binding, retention cannot prove that this
		// operation-complete row is unrelated to a live deletion. Keep it.
		return true, nil
	}
	var status string
	err := tx.QueryRowContext(context.Background(),
		`SELECT status FROM forward_deletion_operations WHERE id = ?`, item.OperationID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: check pending deletion fence: %w", err)
	}
	return status != "COMPLETED", nil
}

func controlInboxLiveProbeFenceByID(tx controlSQL, probeID string) (bool, error) {
	var live int
	if err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(
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

func controlInboxLiveProbeReceiptFence(tx controlSQL, item ControlInboxItem) (bool, error) {
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
	rows, err := tx.QueryContext(context.Background(), `SELECT o.arm_hex
		FROM probe_operations o
		LEFT JOIN probe_terminal_deliveries d ON d.probe_id = o.id
		WHERE o.node_id = ? AND (
			o.status IN ('PENDING', 'ARMED', 'IN_FLIGHT')
			OR (d.probe_id IS NOT NULL AND d.disposition NOT IN ('DELIVERED', 'STALE', 'MISSING', 'EXPIRED'))
		)
		ORDER BY o.expires_at, o.id LIMIT ?`, item.NodeID, pageLimit)
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
			// An invalid live operation is itself a reason to retain this
			// processed receipt, but it must not abort cleanup for unrelated
			// inbox rows. Fail closed for this candidate and continue the outer
			// bounded scan.
			return true, nil
		}
		digest, err := ParseProbeArmLite(armBytes)
		if err != nil {
			// As above, corruption cannot prove that this receipt is safe to
			// discard. Keep it, while allowing cleanup to make progress elsewhere.
			return true, nil
		}
		if digest == want {
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
	return s.finishClaimControlOutboxOperation(res, err, operationID)
}

// ClaimControlOutboxOperationOwned claims one pending row under the current
// durable owner. It is used by live inbound result handling when a result beats
// the reconnect pump.
func (s *Store) ClaimControlOutboxOperationOwned(operationID, messageType string, owner ControlOwner) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE control_outbox SET state = 'CLAIMED', session_id = ?, updated_at = ?
		  WHERE operation_id = ? AND message_type = ? AND state = 'PENDING'
		    AND EXISTS (SELECT 1 FROM nodes
		                 WHERE nodes.id = control_outbox.node_id
		                   AND nodes.current_connection_epoch = ?
		                   AND nodes.current_session_id = ?)`,
		owner.SessionID, now(), operationID, messageType,
		owner.ConnectionEpoch, owner.SessionID,
	)
	return s.finishClaimControlOutboxOperation(res, err, operationID)
}

func (s *Store) finishClaimControlOutboxOperation(res sql.Result, err error, operationID string) error {
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
// This compatibility form is retained for non-session administrative callers;
// live Hub lifecycle code uses SetNodeControlStateOwned.
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

// SetNodeControlStateOwned updates control_state only for the current durable
// owner, preventing stale register/unregister teardown from changing a newer
// session's state.
func (s *Store) SetNodeControlStateOwned(owner ControlOwner, state string) error {
	if err := s.validateOwner(owner); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE nodes SET control_state = ?, updated_at = ?
		WHERE id = ? AND current_connection_epoch = ? AND current_session_id = ?`,
		state, now(), owner.NodeID, owner.ConnectionEpoch, owner.SessionID)
	if err != nil {
		return fmt.Errorf("store: set owned node control state: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set owned node control state rows: %w", err)
	} else if n != 1 {
		return ErrStaleControlOwner
	}
	return nil
}

func (s *Store) validateOwner(owner ControlOwner) error {
	if owner.NodeID == "" || owner.SessionID == "" || owner.ConnectionEpoch == 0 {
		return fmt.Errorf("%w: incomplete control owner", ErrStaleControlOwner)
	}
	return nil
}
