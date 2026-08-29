package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// P10-owned store extension: list/query surface for the minimal admin API
// (Story 4). The frozen schema is unchanged; these are read helpers over the
// existing tables plus the atomic forward-create-with-desired transaction.

// ErrForwardNameConflict identifies the stable (node_id, name) uniqueness
// conflict separately from infrastructure/transaction failures.
var ErrForwardNameConflict = errors.New("store: forward name already exists on node")

// CreateForwardBundle atomically persists a Forward, its initial desired spec,
// its desired-state outbox command, and the idempotency response. The
// idempotency lookup and all inserts run under BEGIN IMMEDIATE so concurrent
// controller processes cannot both pass a read-before-write check. A replay
// returns the original response without touching any forward-side rows.
func (s *Store) CreateForwardBundle(ctx context.Context, f Forward, spec ForwardSpec, outbox ControlOutboxItem, rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	if f.ID == "" || spec.ForwardID != f.ID || outbox.NodeID != f.NodeID {
		return IdempotencyRecord{}, false, errors.New("store: forward bundle identity mismatch")
	}
	if err := s.checkWriteCapacity(); err != nil {
		return IdempotencyRecord{}, false, err
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: begin forward bundle: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	ts := now()
	expires := rec.ExpiresAt
	if expires == 0 {
		expires = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	rec.CreatedAt = ts
	rec.ExpiresAt = expires

	var existing IdempotencyRecord
	err = conn.QueryRowContext(ctx,
		`SELECT key, route, principal, request_hash, response_status,
		        response_body, created_at, expires_at
		   FROM api_idempotency_keys WHERE key = ?`, rec.Key,
	).Scan(&existing.Key, &existing.Route, &existing.Principal, &existing.RequestHash,
		&existing.ResponseStatus, &existing.ResponseBody, &existing.CreatedAt, &existing.ExpiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// New key: continue with the forward-side writes below.
	case err != nil:
		return IdempotencyRecord{}, false, fmt.Errorf("store: get forward idempotency: %w", err)
	case existing.ExpiresAt > ts:
		if existing.Route != rec.Route || existing.Principal != rec.Principal || existing.RequestHash != rec.RequestHash {
			return IdempotencyRecord{}, false, ErrIdempotencyConflict
		}
		return existing, true, nil
	default:
		// Expired keys are replaced only if the complete forward bundle commits;
		// the audit row and delete therefore remain inside this transaction.
		if _, err := conn.ExecContext(ctx, `DELETE FROM api_idempotency_keys WHERE key = ?`, rec.Key); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: expire forward idempotency delete: %w", err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"IDEMPOTENCY_KEY_EXPIRED",
			fmt.Sprintf(`{"key":%q,"route":%q}`, rec.Key, rec.Route), ts); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: forward idempotency expiry audit: %w", err)
		}
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO forwards (id, node_id, name, protocol, current_activation_id,
		                       revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.NodeID, f.Name, f.Protocol, f.CurrentActivationID, f.Revision, ts, ts); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: forwards.node_id, forwards.name") {
			return IdempotencyRecord{}, false, fmt.Errorf("%w: %v", ErrForwardNameConflict, err)
		}
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle forward insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO forward_specs (id, forward_id, revision, spec_json, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		spec.ID, spec.ForwardID, spec.Revision, spec.SpecJSON, ts); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle spec insert: %w", err)
	}
	commandID := deterministicMessageID(outbox.OperationID, outbox.MessageType)
	resultID := deterministicMessageID(commandID, "operation_complete")
	controllerResultID := deterministicMessageID(outbox.OperationID, "operation_complete")
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO control_outbox
		    (operation_id, message_type, node_id, semantic_payload, state,
		     attempt_count, created_at, updated_at, command_message_id,
		     operation_complete_message_id, controller_operation_complete_message_id)
		 VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?, ?)`,
		outbox.OperationID, outbox.MessageType, outbox.NodeID, outbox.SemanticPayload,
		ts, ts, commandID, resultID, controllerResultID); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle outbox insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO api_idempotency_keys
		    (key, route, principal, request_hash, response_status,
		     response_body, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Key, rec.Route, rec.Principal, rec.RequestHash, rec.ResponseStatus,
		rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: forward bundle idempotency insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: commit forward bundle: %w", err)
	}
	committed = true
	return rec, false, nil
}

// ListNodes returns every node in id order.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(
		`SELECT id, name, current_connection_epoch, current_session_id,
		        control_state, revision, created_at, updated_at
		   FROM nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.CurrentConnectionEpoch, &n.CurrentSessionID,
			&n.ControlState, &n.Revision, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ListForwards returns every forward in id order.
func (s *Store) ListForwards() ([]Forward, error) {
	rows, err := s.db.Query(
		`SELECT id, node_id, name, protocol, current_activation_id,
		        revision, created_at, updated_at
		   FROM forwards ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list forwards: %w", err)
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		if err := rows.Scan(&f.ID, &f.NodeID, &f.Name, &f.Protocol, &f.CurrentActivationID,
			&f.Revision, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan forward: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LatestForwardSpec returns the highest-revision spec of a forward.
func (s *Store) LatestForwardSpec(forwardID string) (ForwardSpec, error) {
	var spec ForwardSpec
	err := s.db.QueryRow(
		`SELECT id, forward_id, revision, spec_json, created_at
		   FROM forward_specs WHERE forward_id = ? ORDER BY revision DESC LIMIT 1`,
		forwardID,
	).Scan(&spec.ID, &spec.ForwardID, &spec.Revision, &spec.SpecJSON, &spec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwardSpec{}, ErrNotFound
	}
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("store: latest forward spec: %w", err)
	}
	return spec, nil
}

// CompleteForwardDeletionOperation marks a deletion operation completed.
func (s *Store) CompleteForwardDeletionOperation(id string) error {
	res, err := s.db.Exec(
		`UPDATE forward_deletion_operations SET status = 'COMPLETED', completed_at = ? WHERE id = ?`,
		now(), id,
	)
	if err != nil {
		return fmt.Errorf("store: complete forward deletion operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: complete forward deletion rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// LatestForwardDeletion returns the most recent durable deletion intent for a
// forward. It is used to make duplicate DELETE requests replay the same
// operation instead of enqueueing a second side effect.
func (s *Store) LatestForwardDeletion(forwardID string) (ForwardDeletionOperation, error) {
	var op ForwardDeletionOperation
	var completedAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT id, forward_id, status, desired_revision, created_at, completed_at
		   FROM forward_deletion_operations WHERE forward_id = ?
		   ORDER BY created_at DESC, id DESC LIMIT 1`, forwardID,
	).Scan(&op.ID, &op.ForwardID, &op.Status, &op.DesiredRevision, &op.CreatedAt, &completedAt)
	op.CompletedAt = completedAt.Int64
	if errors.Is(err, sql.ErrNoRows) {
		return ForwardDeletionOperation{}, ErrNotFound
	}
	if err != nil {
		return ForwardDeletionOperation{}, fmt.Errorf("store: latest forward deletion: %w", err)
	}
	return op, nil
}

// ListControlInboxByType returns the durable inbound A2C records of the
// given message types, newest first (bounded). Used by the controller app
// watcher to complete forward-deletion operations when the agent's delete
// result arrives (P10 Story 6 online delete).
func (s *Store) ListControlInboxByType(nodeID string, types ...string) ([]ControlInboxItem, error) {
	if len(types) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(types))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(types)+1)
	for _, t := range types {
		args = append(args, t)
	}
	if nodeID != "" {
		args = append(args, nodeID)
	}
	where := "message_type IN (" + placeholders + ")"
	if nodeID != "" {
		where += " AND node_id = ?"
	}
	rows, err := s.db.Query(
		`SELECT message_id, node_id, message_type, COALESCE(operation_id, ''), semantic_payload, state, updated_at
		   FROM control_inbox WHERE `+where+` ORDER BY id DESC LIMIT 500`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list control inbox: %w", err)
	}
	defer rows.Close()
	var items []ControlInboxItem
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.MessageID, &item.NodeID, &item.MessageType,
			&item.OperationID, &item.SemanticPayload, &item.State, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan control inbox: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListControlInboxByTypeStateLimit returns an ascending keyset page of inbox
// rows in one durable processing state. Unlike the historical newest-500 helper,
// callers can repeatedly drain RECEIVED rows across restarts without stranding
// older deletion results behind newer traffic.
func (s *Store) ListControlInboxByTypeStateLimit(nodeID, state string, limit int, types ...string) ([]ControlInboxItem, error) {
	if state == "" || len(types) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 500
	}
	placeholders := strings.Repeat("?,", len(types))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(types)+3)
	args = append(args, state)
	for _, typ := range types {
		args = append(args, typ)
	}
	where := "state = ? AND message_type IN (" + placeholders + ")"
	if nodeID != "" {
		where += " AND node_id = ?"
		args = append(args, nodeID)
	}
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, message_id, node_id, message_type,
		COALESCE(operation_id, ''), semantic_payload, state, updated_at
		FROM control_inbox WHERE `+where+` ORDER BY id ASC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list inbox state page: %w", err)
	}
	defer rows.Close()
	var items []ControlInboxItem
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.ID, &item.MessageID, &item.NodeID, &item.MessageType,
			&item.OperationID, &item.SemanticPayload, &item.State, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan inbox state page: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListForwardDeletionResultCandidates returns only RECEIVED operation-complete
// rows that are durably identified as the dedicated forward-deletion result.
//
// A generic operation_complete page cannot be used here: ordinary result rows
// may remain RECEIVED until their normal consumer runs and would otherwise
// occupy the whole page forever. The scan therefore uses one bounded,
// process-local high-water/keyset pass over the raw inbox primary key. While
// the outbox row exists, the indexed controller-operation-complete correlation
// is authoritative. After outbox GC, only the inbox operation binding plus the
// deterministic dedicated message id is recoverable without a schema change.
// Payload fields are intentionally not inspected by this enumerator;
// CompleteForwardDeletionMessage validates them after resolving the durable
// deletion operation.
func (s *Store) ListForwardDeletionResultCandidates(limit int) ([]ControlInboxItem, error) {
	if limit <= 0 {
		limit = 500
	}
	if s == nil || s.db == nil {
		return nil, errStoreClosed
	}

	// The recovery cursor is process-local and serialized with Store.Close. It
	// bounds raw inbox work even when ordinary RECEIVED operation_complete rows
	// vastly outnumber dedicated deletion results. Rows arriving after the
	// high-water boundary are considered on the next pass.
	cursor := &s.deletionCandidateCursor
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	if cursor.closed {
		return nil, errStoreClosed
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin deletion candidate scan: %w", err)
	}
	defer tx.Rollback()

	highWater, beforeID := cursor.highWater, cursor.beforeID
	initialized := cursor.initialized
	if !initialized || beforeID <= 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM control_inbox`).Scan(&highWater); err != nil {
			return nil, fmt.Errorf("store: read deletion candidate high-water: %w", err)
		}
		if highWater == 0 {
			if err := tx.Commit(); err != nil {
				return nil, fmt.Errorf("store: commit empty deletion candidate scan: %w", err)
			}
			cursor.resetLocked()
			return nil, nil
		}
		beforeID = highWater
		initialized = true
	}

	// Do not put state/type/deletion filters in this query. With a filtered
	// LIMIT, an ordinary-row prefix could force SQLite to examine an unbounded
	// number of unrelated entries. The INTEGER PRIMARY KEY keyset plus
	// NOT INDEXED makes the raw examined-row budget explicit.
	rows, err := tx.QueryContext(ctx, `
		SELECT id, message_id, node_id, message_type,
		       COALESCE(operation_id, ''), semantic_payload, state, updated_at
		  FROM control_inbox NOT INDEXED
		 WHERE id <= ? AND id > 0
		 ORDER BY id DESC
		 LIMIT ?`, beforeID, maxControlInboxCleanupScan)
	if err != nil {
		return nil, fmt.Errorf("store: list deletion candidate scan: %w", err)
	}

	// Materialize the bounded raw page before issuing classification lookups.
	// Some SQLite drivers do not permit a second statement on a transaction
	// while the first statement still has an active cursor. The raw scan is
	// already bounded by maxControlInboxCleanupScan, so retaining this page is
	// also a bounded allocation.
	rawItems := make([]ControlInboxItem, 0, maxControlInboxCleanupScan)
	for rows.Next() {
		var item ControlInboxItem
		if err := rows.Scan(&item.ID, &item.MessageID, &item.NodeID,
			&item.MessageType, &item.OperationID, &item.SemanticPayload,
			&item.State, &item.UpdatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan deletion candidate row: %w", err)
		}
		rawItems = append(rawItems, item)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: close deletion candidate scan: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read deletion candidate scan: %w", err)
	}

	candidateCapacity := limit
	if candidateCapacity > maxControlInboxCleanupScan {
		candidateCapacity = maxControlInboxCleanupScan
	}
	candidates := make([]ControlInboxItem, 0, candidateCapacity)
	lastExaminedID := int64(0)
	for _, item := range rawItems {
		lastExaminedID = item.ID
		if item.State != ControlInboxReceived || item.MessageType != "operation_complete" {
			continue
		}

		// Check both exact result correlations independently. The controller
		// correlation has precedence: if it exists, only a row that joins to a
		// durable forward-deletion operation is eligible. A normal result
		// correlation belongs to the ordinary result consumer and suppresses
		// direct post-GC recovery. Neither branch inspects the payload.
		var controllerCorrelation, normalCorrelation int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1
			  FROM control_outbox
			 WHERE node_id = ?
			   AND controller_operation_complete_message_id = ?
		)`, item.NodeID, item.MessageID).Scan(&controllerCorrelation); err != nil {
			return nil, fmt.Errorf("store: check controller deletion correlation: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1
			  FROM control_outbox
			 WHERE node_id = ?
			   AND operation_complete_message_id = ?
		)`, item.NodeID, item.MessageID).Scan(&normalCorrelation); err != nil {
			return nil, fmt.Errorf("store: check normal result correlation: %w", err)
		}

		eligible := false
		if controllerCorrelation == 1 {
			var live int
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
				SELECT 1
				  FROM control_outbox o
				  JOIN forward_deletion_operations d ON d.id = o.operation_id
				 WHERE o.node_id = ?
				   AND o.controller_operation_complete_message_id = ?
			)`, item.NodeID, item.MessageID).Scan(&live); err != nil {
				return nil, fmt.Errorf("store: check live deletion candidate: %w", err)
			}
			eligible = live == 1
		} else if normalCorrelation == 0 &&
			item.OperationID != "" &&
			item.MessageID == deterministicMessageID(item.OperationID, "operation_complete") {
			// After outbox GC, only a direct dedicated binding is recoverable.
			// A normal Agent result binds to the command message id; SHA-256
			// message ids are one-way, so direct recovery is considered only
			// when neither result correlation exists.
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
				SELECT 1 FROM forward_deletion_operations WHERE id = ?
			)`, item.OperationID).Scan(&exists); err != nil {
				return nil, fmt.Errorf("store: check recovered deletion operation: %w", err)
			}
			eligible = exists == 1
		}
		if eligible {
			candidates = append(candidates, item)
			// Do not consume rows beyond the caller's result limit. Advancing to
			// the last row actually examined keeps the next call from skipping a
			// candidate that would otherwise be trimmed from the returned page.
			if len(candidates) == limit {
				break
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit deletion candidate scan: %w", err)
	}

	// The scan is descending for bounded keyset progress; API callers receive
	// candidates in durable inbox order.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	if lastExaminedID == 0 || lastExaminedID <= 1 {
		cursor.resetLocked()
	} else {
		cursor.highWater = highWater
		cursor.beforeID = lastExaminedID - 1
		cursor.initialized = initialized
	}
	return candidates, nil
}

// ControlInboxItemByMessageID returns one exact durable inbox record. It is
// used by correlation paths that must not substitute a payload-supplied id.
func (s *Store) ControlInboxItemByMessageID(messageID string) (ControlInboxItem, error) {
	var item ControlInboxItem
	err := s.db.QueryRow(`SELECT id, message_id, node_id, message_type,
		COALESCE(operation_id, ''), semantic_payload, state, updated_at
		FROM control_inbox WHERE message_id = ?`, messageID).Scan(
		&item.ID, &item.MessageID, &item.NodeID, &item.MessageType,
		&item.OperationID, &item.SemanticPayload, &item.State, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlInboxItem{}, ErrNotFound
	}
	if err != nil {
		return ControlInboxItem{}, fmt.Errorf("store: get inbox message: %w", err)
	}
	return item, nil
}

// BindControlInboxOperationID fills the operation discriminator on a legacy
// inbox tombstone that predates the correlation column. The caller must have
// independently matched the authenticated envelope to the indexed outbox
// row; this method only permits the one-way NULL/empty -> exact binding.
func (s *Store) BindControlInboxOperationID(messageID, operationID string) error {
	if messageID == "" || operationID == "" {
		return ErrCASConflict
	}
	res, err := s.db.Exec(`UPDATE control_inbox SET operation_id = ?, updated_at = ?
		WHERE message_id = ? AND (operation_id IS NULL OR operation_id = '')`,
		operationID, s.currentUnix(), messageID)
	if err != nil {
		return fmt.Errorf("store: bind inbox operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: bind inbox operation rows: %w", err)
	} else if n == 1 {
		return nil
	}
	item, err := s.ControlInboxItemByMessageID(messageID)
	if err != nil {
		return err
	}
	if item.OperationID == operationID {
		return nil
	}
	return fmt.Errorf("%w: inbox message %q operation binding differs", ErrMessageConflict, messageID)
}

// durableDeletionResultCorrelation validates the result/message binding after
// the originating outbox row has been garbage-collected. The normal P10 delete
// command is "desired"; the legacy explicit delete message is retained only
// for databases/protocol fixtures that used that command name.
func durableDeletionResultCorrelation(messageID, inboxOperation, deletionOperationID string) bool {
	if inboxOperation == deletionOperationID &&
		messageID == deterministicMessageID(deletionOperationID, "operation_complete") {
		return true
	}
	for _, messageType := range []string{"desired", "C2A_FORWARD_DELETE"} {
		commandID := deterministicMessageID(deletionOperationID, messageType)
		if inboxOperation == commandID && messageID == deterministicMessageID(commandID, "operation_complete") {
			return true
		}
	}
	return false
}

// permanentDeletionResultError adds the narrow terminal classification while
// retaining the historical store sentinel for callers that distinguish a
// correlation/CAS failure from other storage errors. The watcher keys only on
// ErrPermanentDeletionResult; the wrapped cause remains diagnostic/API
// compatible.
func permanentDeletionResultError(cause error, format string, args ...any) error {
	if cause == nil {
		cause = ErrCASConflict
	}
	values := make([]any, 0, len(args)+2)
	values = append(values, ErrPermanentDeletionResult, cause)
	values = append(values, args...)
	return fmt.Errorf("%w: %w: "+format, values...)
}

// CompleteForwardDeletionMessage atomically applies the dedicated forward
// deletion result identified by its durable inbox message id. The message id
// and inbox operation binding are the correlation authority; payload ids are
// checked only as assertions after the durable deletion operation is resolved.
// Ordinary operation_complete results return ErrNotFound and remain available
// to their normal consumer.
func (s *Store) CompleteForwardDeletionMessage(messageID string) error {
	return s.completeForwardDeletionMessage(messageID, false, "", "")
}

// CompleteForwardDeletionResult is the historical compatibility entry point
// for callers that also have the deletion and forward ids. The ids are
// assertions only: messageID is resolved against the indexed outbox result
// correlation before either assertion is checked. The compatibility path may
// recognize the normal operation_complete correlation while the canonical
// watcher remains dedicated-result-only; after outbox GC only the dedicated
// inbox binding is recoverable.
func (s *Store) CompleteForwardDeletionResult(messageID, deletionOperationID, forwardID string) error {
	if messageID == "" || deletionOperationID == "" || forwardID == "" {
		return permanentDeletionResultError(ErrCASConflict, "deletion result identity is incomplete")
	}
	return s.completeForwardDeletionMessage(messageID, true, deletionOperationID, forwardID)
}

// completeForwardDeletionMessage performs the canonical message-centric
// completion transaction. expectedDeletionOperationID and expectedForwardID
// are optional caller assertions used only by CompleteForwardDeletionResult;
// neither is ever used to select a durable row. When allowNormalResult is
// false, only the dedicated controller-operation-complete outbox correlation
// can identify a live deletion result. When it is true, the compatibility
// caller may additionally use the indexed normal operation_complete result.
func (s *Store) completeForwardDeletionMessage(messageID string, allowNormalResult bool, expectedDeletionOperationID, expectedForwardID string) error {
	if messageID == "" {
		return permanentDeletionResultError(ErrCASConflict, "deletion result message id is required")
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("store: deletion result conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin deletion result: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var inboxNode, inboxType, inboxOperation, inboxPayload, inboxState string
	if err := conn.QueryRowContext(context.Background(), `SELECT node_id, message_type,
		COALESCE(operation_id, ''), semantic_payload, state
		FROM control_inbox WHERE message_id = ?`, messageID).
		Scan(&inboxNode, &inboxType, &inboxOperation, &inboxPayload, &inboxState); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read deletion result inbox: %w", err)
	}
	if inboxType != "operation_complete" {
		return ErrNotFound
	}

	// Resolve the durable deletion operation from the result message id first.
	// The dedicated controller result has precedence. The normal result is
	// accepted only by the compatibility wrapper, never by the watcher.
	var deletionOperationID, outboxNode string
	correlationFound := false
	err = conn.QueryRowContext(context.Background(), `SELECT operation_id, node_id
		FROM control_outbox
		WHERE node_id = ? AND controller_operation_complete_message_id = ?
		LIMIT 1`, inboxNode, messageID).Scan(&deletionOperationID, &outboxNode)
	if err == nil {
		correlationFound = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: resolve deletion result correlation: %w", err)
	}
	if !correlationFound && allowNormalResult {
		err = conn.QueryRowContext(context.Background(), `SELECT operation_id, node_id
			FROM control_outbox
			WHERE node_id = ? AND operation_complete_message_id = ?
			LIMIT 1`, inboxNode, messageID).Scan(&deletionOperationID, &outboxNode)
		if err == nil {
			correlationFound = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: resolve compatibility deletion result correlation: %w", err)
		}
	}
	if !correlationFound {
		// After outbox GC, only a dedicated result can be recovered without a
		// historical operation/message mapping. A normal result's inbox binding
		// is the Agent command id, not the deletion operation id.
		if inboxOperation == "" || messageID != deterministicMessageID(inboxOperation, "operation_complete") {
			return ErrNotFound
		}
		// An ordinary command result can have the same inbox operation binding
		// and deterministic message shape as a deletion operation. Once the
		// outbox row is gone, refuse the fallback whenever the exact normal
		// result correlation exists; only an uncorrelated dedicated binding is
		// recoverable here.
		var normalCorrelation int
		if err := conn.QueryRowContext(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM control_outbox
			 WHERE node_id = ? AND operation_complete_message_id = ?
		)`, inboxNode, messageID).Scan(&normalCorrelation); err != nil {
			return fmt.Errorf("store: check normal deletion correlation: %w", err)
		}
		if normalCorrelation == 1 {
			return ErrNotFound
		}
		deletionOperationID = inboxOperation
	}
	if correlationFound && outboxNode != inboxNode {
		return permanentDeletionResultError(ErrCASConflict, "deletion result node correlation mismatch")
	}

	var durableForwardID, deletionStatus string
	if err := conn.QueryRowContext(context.Background(), `SELECT forward_id, status
		FROM forward_deletion_operations WHERE id = ?`, deletionOperationID).
		Scan(&durableForwardID, &deletionStatus); errors.Is(err, sql.ErrNoRows) {
		// A correlated controller result can exist for a non-deletion operation.
		// It is not a deletion candidate and must not poison that operation.
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read deletion operation: %w", err)
	}

	// Compatibility arguments are checked only after the message-centric
	// outbox/inbox correlation and durable operation lookup above. In
	// particular, they never steer either SELECT or the mutation below.
	if expectedDeletionOperationID != "" && expectedDeletionOperationID != deletionOperationID {
		return permanentDeletionResultError(ErrCASConflict, "deletion operation assertion mismatch")
	}
	if expectedForwardID != "" && expectedForwardID != durableForwardID {
		return permanentDeletionResultError(ErrCASConflict, "forward assertion mismatch")
	}

	var result struct {
		ForwardID           string `json:"forward_id"`
		DeletionOperationID string `json:"deletion_operation_id"`
		Deleted             bool   `json:"deleted"`
	}
	if err := protocol.DecodeStrictJSONInto([]byte(inboxPayload), &result); err != nil ||
		!result.Deleted || result.ForwardID == "" || result.DeletionOperationID == "" {
		return permanentDeletionResultError(ErrCASConflict, "malformed deletion result payload")
	}
	if result.DeletionOperationID != deletionOperationID || result.ForwardID != durableForwardID {
		return permanentDeletionResultError(ErrCASConflict, "deletion result payload does not match durable operation")
	}

	var forwardNode string
	if err := conn.QueryRowContext(context.Background(), `SELECT node_id FROM forwards WHERE id = ?`, durableForwardID).
		Scan(&forwardNode); errors.Is(err, sql.ErrNoRows) {
		return permanentDeletionResultError(ErrForwardNotFound, "forward %q is absent", durableForwardID)
	} else if err != nil {
		return fmt.Errorf("store: read deletion forward: %w", err)
	}
	if inboxNode != forwardNode {
		return permanentDeletionResultError(ErrCASConflict, "deletion result node mismatch")
	}
	if deletionStatus != "PENDING" && deletionStatus != "COMPLETED" {
		return fmt.Errorf("%w: deletion operation is %s", ErrCASConflict, deletionStatus)
	}
	if deletionStatus == "PENDING" {
		res, err := conn.ExecContext(context.Background(), `UPDATE forward_deletion_operations
			SET status = 'COMPLETED', completed_at = ?
			WHERE id = ? AND forward_id = ? AND status = 'PENDING'`, now(), deletionOperationID, durableForwardID)
		if err != nil {
			return fmt.Errorf("store: complete deletion operation: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("store: complete deletion rows: %w", err)
		} else if n != 1 {
			return ErrCASConflict
		}
	}
	if inboxState != ControlInboxProcessed {
		res, err := conn.ExecContext(context.Background(), `UPDATE control_inbox SET state = 'PROCESSED', updated_at = ?
			WHERE message_id = ? AND state = 'RECEIVED'`, now(), messageID)
		if err != nil {
			return fmt.Errorf("store: mark deletion result processed: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: mark deletion result processed rows: %w", err)
		}
		if n != 1 {
			var current string
			if err := conn.QueryRowContext(context.Background(),
				`SELECT state FROM control_inbox WHERE message_id = ?`, messageID).Scan(&current); err != nil {
				return fmt.Errorf("store: recheck deletion result state: %w", err)
			}
			return fmt.Errorf("%w: deletion result inbox is %s, want RECEIVED", ErrCASConflict, current)
		}
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return fmt.Errorf("store: commit deletion result: %w", err)
	}
	committed = true
	return nil
}

func (s *Store) CountEnrollmentTokens() (int, error) {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM node_enrollment_tokens").Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count enrollment tokens: %w", err)
	}
	return count, nil
}
