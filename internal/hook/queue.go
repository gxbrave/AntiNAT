package hook

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
)

// QueueFull policies (versioned; v0.8 §8.1 "never silent loss").
const (
	OnFullCoalesce = "coalesce"
	OnFullDrop     = "drop"
	OnFullDLQ      = "dlq"
)

// Defaults applied when a QueuePolicy field is zero.
const (
	defaultMaxQueue    = 100
	defaultMaxAttempts = 8
)

// QueuePolicy is the versioned per-event queue policy.
type QueuePolicy struct {
	Version     int    `json:"version"`
	OnFull      string `json:"on_full"`
	MaxQueue    int    `json:"max_queue,omitempty"`
	MaxAttempts int    `json:"max_attempts,omitempty"`
}

// Normalized returns the policy with defaults applied.
func (p QueuePolicy) Normalized() QueuePolicy {
	if p.Version <= 0 {
		p.Version = 1
	}
	if p.OnFull != OnFullCoalesce && p.OnFull != OnFullDrop && p.OnFull != OnFullDLQ {
		p.OnFull = OnFullDLQ
	}
	if p.MaxQueue <= 0 {
		p.MaxQueue = defaultMaxQueue
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaultMaxAttempts
	}
	return p
}

func (p QueuePolicy) toJSON() string {
	raw, _ := json.Marshal(p.Normalized())
	return string(raw)
}

// Event is one durable delivery request. EventID is the stable dedupe key:
// enqueuing the same (hook_id, event_id) twice is an idempotent no-op.
type Event struct {
	HookID   string
	EventID  string
	Kind     string
	NodeID   string
	Payload  []byte
	Policy   QueuePolicy
	Script   []byte // optional isolated-JS script (base64 when persisted)
	SecretID string // optional secret used by the broker to sign this delivery
}

// AppendAudit writes a durable admin_events row (the SSE Last-Event-ID audit
// surface). The hook store reuses the frozen admin_events table for
// queue-full drops / DLQ / decommission transitions so loss is never silent.
func (s *Store) AppendAudit(eventType, payload string) error {
	_, err := s.db.Exec(
		`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
		eventType, payload, s.currentUnix())
	if err != nil {
		return fmt.Errorf("hook: append audit: %w", err)
	}
	return nil
}

func (s *Store) auditFor(eventType, payload string) {
	_ = s.AppendAudit(eventType, payload)
}

// EnqueueEvent durably queues one delivery. It is idempotent for a repeated
// (hook_id, event_id) and applies the versioned queue-full policy when the
// hook's pending+inflight backlog is at the bound.
func (s *Store) EnqueueEvent(evt Event) (Delivery, error) {
	if evt.HookID == "" || evt.EventID == "" {
		return Delivery{}, fmt.Errorf("%w: hook_id and event_id are required", ErrInvalid)
	}
	policy := evt.Policy.Normalized()
	kind := evt.Kind
	if kind == "" {
		kind = "lifecycle"
	}
	if _, err := s.GetDefinition(evt.HookID); err != nil {
		return Delivery{}, err
	}
	ts := s.currentUnix()
	tx, err := s.beginImmediate()
	if err != nil {
		return Delivery{}, err
	}
	defer func() {
		_ = tx.Close()
	}()

	// Duplicate tolerance: a stable event_id never creates a second delivery.
	var existingID string
	var existingState string
	err = tx.QueryRow(`SELECT id, state FROM hook_deliveries WHERE hook_id = ? AND event_id = ?`,
		evt.HookID, evt.EventID).Scan(&existingID, &existingState)
	switch {
	case err == nil:
		_ = tx.Rollback()
		return s.GetDelivery(existingID)
	case !errors.Is(err, sql.ErrNoRows):
		_ = tx.Rollback()
		return Delivery{}, fmt.Errorf("hook: enqueue duplicate lookup: %w", err)
	}

	// Queue-full gate: count the hook's pending+inflight backlog.
	var backlogue int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM hook_deliveries
		  WHERE hook_id = ? AND state IN ('PENDING','IN_FLIGHT','FAILED')`,
		evt.HookID).Scan(&backlogue); err != nil {
		_ = tx.Rollback()
		return Delivery{}, fmt.Errorf("hook: queue length: %w", err)
	}
	if backlogue >= policy.MaxQueue {
		return s.enqueueFull(tx, evt, policy, kind, ts)
	}
	d, err := insertDelivery(tx, evt, policy, kind, DeliveryPending, ts, ts, "")
	if err != nil {
		_ = tx.Rollback()
		return Delivery{}, err
	}
	if err := tx.Commit(); err != nil {
		return Delivery{}, fmt.Errorf("hook: commit enqueue: %w", err)
	}
	return d, nil
}

// enqueueFull applies the versioned on_full policy atomically inside tx.
func (s *Store) enqueueFull(tx *dbTX, evt Event, policy QueuePolicy, kind string, ts int64) (Delivery, error) {
	switch policy.OnFull {
	case OnFullCoalesce:
		// A burst of state events for the same destination collapses to the
		// latest payload (coalesce key: hook + event kind). The newest event
		// id and payload replace the pending item; if there is nothing to
		// coalesce into, fall through to the DLQ path.
		var targetID string
		err := tx.QueryRow(`SELECT id FROM hook_deliveries
			WHERE hook_id = ? AND kind = ? AND state IN ('PENDING','FAILED')
			ORDER BY created_at LIMIT 1`, evt.HookID, kind).Scan(&targetID)
		if err == nil {
			if _, upErr := tx.Exec(`UPDATE hook_deliveries
				SET event_id = ?, payload_json = ?, script_b64 = ?, secret_id = ?, updated_at = ?
				WHERE id = ?`, evt.EventID, string(evt.Payload), b64Str(evt.Script), evt.SecretID, ts, targetID); upErr != nil {
				_ = tx.Rollback()
				return Delivery{}, fmt.Errorf("hook: coalesce update: %w", upErr)
			}
			if err := tx.Commit(); err != nil {
				return Delivery{}, fmt.Errorf("hook: commit coalesce: %w", err)
			}
			s.auditFor("HOOK_DELIVERY_COALESCED", fmt.Sprintf(`{"delivery_id":%q,"hook_id":%q,"event_id":%q}`, targetID, evt.HookID, evt.EventID))
			return s.GetDelivery(targetID)
		}
		// No coalesce target: treat as a drop-style DLQ so nothing is silent.
		d, err := insertDelivery(tx, evt, policy, kind, DeliveryDLQed, ts, ts, "queue coalesce fallback to DLQ")
		if err != nil {
			_ = tx.Rollback()
			return Delivery{}, err
		}
		if err := tx.Commit(); err != nil {
			return Delivery{}, fmt.Errorf("hook: commit coalesce-dlq: %w", err)
		}
		s.auditFor("HOOK_DELIVERY_DLQED", fmt.Sprintf(`{"delivery_id":%q,"hook_id":%q,"event_id":%q,"reason":%q}`, d.ID, evt.HookID, evt.EventID, "queue full, no coalesce target"))
		return d, nil
	case OnFullDrop:
		_ = tx.Rollback()
		s.auditFor("HOOK_DELIVERY_DROPPED", fmt.Sprintf(`{"hook_id":%q,"event_id":%q,"policy":"drop"}`, evt.HookID, evt.EventID))
		return Delivery{}, fmt.Errorf("%w: hook %s dropped event %s", ErrQueueFull, evt.HookID, evt.EventID)
	default:
		d, err := insertDelivery(tx, evt, policy, kind, DeliveryDLQed, ts, ts, "queue full (DLQ policy)")
		if err != nil {
			_ = tx.Rollback()
			return Delivery{}, err
		}
		if err := tx.Commit(); err != nil {
			return Delivery{}, fmt.Errorf("hook: commit dlq: %w", err)
		}
		s.auditFor("HOOK_DELIVERY_DLQED", fmt.Sprintf(`{"delivery_id":%q,"hook_id":%q,"event_id":%q,"reason":%q}`, d.ID, evt.HookID, evt.EventID, "queue full"))
		return d, nil
	}
}

func insertDelivery(tx execer, evt Event, policy QueuePolicy, kind, state string, ts, next int64, lastError string) (Delivery, error) {
	id := randomHookID()
	_, err := tx.Exec(`INSERT INTO hook_deliveries
		(id, hook_id, event_id, kind, state, attempt_count, max_attempts, next_attempt_at,
		 policy_json, payload_json, script_b64, secret_id, last_error, node_id,
		 decommission_deadline, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, evt.HookID, evt.EventID, kind, state, policy.MaxAttempts, next,
		policy.toJSON(), string(evt.Payload), b64Str(evt.Script), evt.SecretID,
		lastError, evt.NodeID, ts, ts)
	if err != nil {
		return Delivery{}, fmt.Errorf("hook: insert delivery: %w", err)
	}
	return Delivery{
		ID: id, HookID: evt.HookID, EventID: evt.EventID, Kind: kind, State: state,
		MaxAttempts: policy.MaxAttempts, NextAttemptAt: next, PolicyJSON: policy.toJSON(),
		PayloadJSON: string(evt.Payload), ScriptB64: b64Str(evt.Script), SecretID: evt.SecretID,
		LastError: lastError, NodeID: evt.NodeID, CreatedAt: ts, UpdatedAt: ts,
	}, nil
}

func b64Str(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// GetDelivery returns one delivery.
func (s *Store) GetDelivery(id string) (Delivery, error) {
	return scanDelivery(s.db.QueryRow(
		`SELECT id, hook_id, event_id, kind, state, attempt_count, max_attempts,
		        next_attempt_at, policy_json, payload_json, script_b64, secret_id,
		        last_error, node_id, decommission_deadline, created_at, updated_at
		   FROM hook_deliveries WHERE id = ?`, id))
}

func scanDelivery(row *sql.Row) (Delivery, error) {
	var d Delivery
	err := row.Scan(&d.ID, &d.HookID, &d.EventID, &d.Kind, &d.State, &d.AttemptCount,
		&d.MaxAttempts, &d.NextAttemptAt, &d.PolicyJSON, &d.PayloadJSON, &d.ScriptB64,
		&d.SecretID, &d.LastError, &d.NodeID, &d.DecommissionDeadline, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, ErrNotFound
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("hook: scan delivery: %w", err)
	}
	return d, nil
}

// inFlightStuckSeconds requeues an IN_FLIGHT delivery back to PENDING after
// this age so a dispatcher crash mid-send never loses the at-least-once
// promise. The dispatcher must complete within a bounded window.
const inFlightStuckSeconds = 300

// ClaimDue atomically marks up to max due PENDING deliveries as IN_FLIGHT for
// the dispatcher, first dropping decommissioned rows past their deadline and
// requeueing stuck IN_FLIGHT rows. It returns the claimed deliveries.
func (s *Store) ClaimDue(max int) ([]Delivery, error) {
	if max <= 0 {
		return nil, nil
	}
	ts := s.currentUnix()
	tx, err := s.beginImmediate()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Close()
	}()

	// Requeue stuck in-flight rows (dispatcher crashed mid-send).
	_, err = tx.Exec(`UPDATE hook_deliveries
		SET state = ?, next_attempt_at = ?, updated_at = ?
		WHERE state = ? AND updated_at < ?`,
		DeliveryPending, ts, ts, DeliveryInFlight, ts-inFlightStuckSeconds)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("hook: requeue stuck: %w", err)
	}

	// Decommission drop: after the deadline these bounded best-effort rows are
	// dropped with a durable audit (never retried, never a silent loss).
	drops, err := tx.Query(`SELECT id, hook_id, event_id, node_id FROM hook_deliveries
		WHERE decommission_deadline > 0 AND decommission_deadline <= ?
		  AND state IN ('PENDING','IN_FLIGHT','FAILED')`, ts)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("hook: decommission scan: %w", err)
	}
	var dropRows []struct{ id, hookID, eventID, nodeID string }
	for drops.Next() {
		var r struct{ id, hookID, eventID, nodeID string }
		if err := drops.Scan(&r.id, &r.hookID, &r.eventID, &r.nodeID); err != nil {
			drops.Close()
			_ = tx.Rollback()
			return nil, fmt.Errorf("hook: scan decommission drop: %w", err)
		}
		dropRows = append(dropRows, r)
	}
	if err := drops.Close(); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := drops.Err(); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	for _, r := range dropRows {
		if _, err := tx.Exec(`UPDATE hook_deliveries SET state = ?, updated_at = ? WHERE id = ?`,
			DeliveryDroppedDecommission, ts, r.id); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("hook: drop decommissioned: %w", err)
		}
		// Audit in the same transaction so a drop is never silent.
		if _, err := tx.Exec(`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"HOOK_DELIVERY_DROPPED_DUE_TO_DECOMMISSION",
			fmt.Sprintf(`{"delivery_id":%q,"hook_id":%q,"event_id":%q,"node_id":%q}`, r.id, r.hookID, r.eventID, r.nodeID),
			ts); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("hook: audit decommission drop: %w", err)
		}
	}

	rows, err := tx.Query(`SELECT id FROM hook_deliveries
		WHERE state IN (?, ?) AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?`,
		DeliveryPending, DeliveryFailed, ts, max)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("hook: claim select: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			_ = tx.Rollback()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return nil, err
	}

	deliveries := make([]Delivery, 0, len(ids))
	for _, id := range ids {
		if _, err := tx.Exec(`UPDATE hook_deliveries SET state = ?, updated_at = ? WHERE id = ? AND state IN (?, ?)`,
			DeliveryInFlight, ts, id, DeliveryPending, DeliveryFailed); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("hook: claim update: %w", err)
		}
		deliveries = append(deliveries, Delivery{ID: id, HookID: "", EventID: "", State: DeliveryInFlight})
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("hook: commit claim: %w", err)
	}
	// Re-read the full rows outside the transaction for the dispatcher.
	full := make([]Delivery, 0, len(ids))
	for _, id := range ids {
		d, err := s.GetDelivery(id)
		if err != nil {
			return nil, err
		}
		full = append(full, d)
	}
	return full, nil
}

// MarkDelivered records a terminal success for a claimed delivery.
func (s *Store) MarkDelivered(id string) error {
	ts := s.currentUnix()
	var affected int64
	res, err := s.db.Exec(`UPDATE hook_deliveries
		SET state = ?, last_error = '', updated_at = ? WHERE id = ? AND state = ?`,
		DeliveryDelivered, ts, id, DeliveryInFlight)
	if err != nil {
		return fmt.Errorf("hook: mark delivered: %w", err)
	}
	affected, _ = res.RowsAffected()
	if affected == 1 {
		return nil
	}
	// The row may already be terminal (duplicate finalize): tolerate, but
	// refuse to resurrect a dropped/delivered row by a stale IN_FLIGHT writer.
	if _, err := s.GetDelivery(id); errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return nil
}

// MarkFailed records a transient failure (with bounded backoff) or, at the
// attempt bound, the terminal DLQ state. The error message never contains
// secret material (callers pass a scrubbed message).
func (s *Store) MarkFailed(id, errMsg string) error {
	ts := s.currentUnix()
	var d Delivery
	err := s.db.QueryRow(`SELECT state, attempt_count, max_attempts FROM hook_deliveries WHERE id = ?`, id).
		Scan(&d.State, &d.AttemptCount, &d.MaxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("hook: mark failed read: %w", err)
	}
	if d.State != DeliveryInFlight {
		return nil // stale writer; the claim already moved on
	}
	attempt := d.AttemptCount + 1
	next := ts + backoffSeconds(attempt, s.jitter)
	if attempt >= d.MaxAttempts {
		if _, err := s.db.Exec(`UPDATE hook_deliveries
			SET state = ?, attempt_count = ?, last_error = ?, updated_at = ?
			WHERE id = ? AND state = ?`,
			DeliveryDLQed, attempt, errMsg, ts, id, DeliveryInFlight); err != nil {
			return fmt.Errorf("hook: mark dlq: %w", err)
		}
		s.auditFor("HOOK_DELIVERY_DLQED", fmt.Sprintf(`{"delivery_id":%q,"reason":%q}`, id, "max attempts reached"))
		return nil
	}
	if _, err := s.db.Exec(`UPDATE hook_deliveries
		SET state = ?, attempt_count = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
		WHERE id = ? AND state = ?`,
		DeliveryFailed, attempt, next, errMsg, ts, id, DeliveryInFlight); err != nil {
		return fmt.Errorf("hook: mark failed: %w", err)
	}
	return nil
}

// RetryDelivery requeues a FAILED or DLQED delivery as PENDING with a fresh
// attempt budget (name matches the frozen POST /hook-deliveries/{id}/retry).
func (s *Store) RetryDelivery(id string) (Delivery, error) {
	ts := s.currentUnix()
	res, err := s.db.Exec(`UPDATE hook_deliveries
		SET state = ?, attempt_count = 0, next_attempt_at = ?, last_error = '', updated_at = ?
		WHERE id = ? AND state IN (?, ?)`,
		DeliveryPending, ts, ts, id, DeliveryFailed, DeliveryDLQed)
	if err != nil {
		return Delivery{}, fmt.Errorf("hook: retry delivery: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, getErr := s.GetDelivery(id); errors.Is(getErr, ErrNotFound) {
			return Delivery{}, ErrNotFound
		}
		return Delivery{}, fmt.Errorf("%w: delivery %s is not retryable", ErrInvalid, id)
	}
	s.auditFor("HOOK_DELIVERY_RETRY", fmt.Sprintf(`{"delivery_id":%q}`, id))
	return s.GetDelivery(id)
}

// MarkDecommissioned bounds delivery best-effort for a node: deliveries
// targeting the node are dropped after the deadline (Dispatcher applies the
// drop; this just arms the deadline).
func (s *Store) MarkDecommissioned(nodeID string, deadline int64) error {
	if nodeID == "" {
		return fmt.Errorf("%w: node_id is required", ErrInvalid)
	}
	if deadline <= 0 {
		return fmt.Errorf("%w: deadline must be in the future", ErrInvalid)
	}
	ts := s.currentUnix()
	res, err := s.db.Exec(`UPDATE hook_deliveries
		SET decommission_deadline = ?, updated_at = ?
		WHERE node_id = ? AND state IN ('PENDING','IN_FLIGHT','FAILED')`,
		deadline, ts, nodeID)
	if err != nil {
		return fmt.Errorf("hook: mark decommissioned: %w", err)
	}
	n, _ := res.RowsAffected()
	s.auditFor("HOOK_DECOMMISSION_MARKED", fmt.Sprintf(`{"node_id":%q,"deadline":%d,"affected":%d}`, nodeID, deadline, n))
	return nil
}

// ListDeliveries returns deliveries for observability, newest first.
func (s *Store) ListDeliveries(limit int) ([]Delivery, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, hook_id, event_id, kind, state, attempt_count,
		max_attempts, next_attempt_at, policy_json, payload_json, script_b64, secret_id,
		last_error, node_id, decommission_deadline, created_at, updated_at
		FROM hook_deliveries ORDER BY created_at DESC, id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("hook: list deliveries: %w", err)
	}
	var out []Delivery
	if err := scanAll(rows, nil, func(r *sql.Rows) error {
		var d Delivery
		if err := r.Scan(&d.ID, &d.HookID, &d.EventID, &d.Kind, &d.State, &d.AttemptCount,
			&d.MaxAttempts, &d.NextAttemptAt, &d.PolicyJSON, &d.PayloadJSON, &d.ScriptB64,
			&d.SecretID, &d.LastError, &d.NodeID, &d.DecommissionDeadline, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return err
		}
		out = append(out, d)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// AdminEvents returns the durable admin_events event types for the hook
// subsystem (queue drops / DLQ / decommission transitions are never silent).
func (s *Store) AdminEvents(limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT event_type FROM admin_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("hook: list admin events: %w", err)
	}
	var out []string
	if err := scanAll(rows, nil, func(r *sql.Rows) error {
		var kind string
		if err := r.Scan(&kind); err != nil {
			return err
		}
		out = append(out, kind)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// BackoffSeconds is the exported bounded exponential backoff curve for an
// attempt (1s,2s,4s,8s,16s,32s,64s,128s then capped at 300s).
func BackoffSeconds(attempt int) int64 {
	return backoffSeconds(attempt, nil)
}

// backoffSeconds returns the bounded exponential backoff for an attempt
// (1s,2s,4s,... capped at 5 minutes, ±jitter).
func backoffSeconds(attempt int, jitter func(int64) int64) int64 {
	if attempt <= 0 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	base := int64(1) << (attempt - 1)
	if base < 1 {
		base = 1
	}
	if base > 300 {
		base = 300
	}
	if jitter != nil {
		base += jitter(base / 5)
	}
	if base < 1 {
		base = 1
	}
	if base > 300 {
		base = 300
	}
	return base
}

// jitter returns a deterministic pseudo-random offset for backoff.
func (s *Store) jitter(max int64) int64 {
	if s == nil || s.jitterFn == nil {
		if max <= 0 {
			return 0
		}
		return rand.Int63n(max + 1)
	}
	return s.jitterFn(max)
}

// SetJitter injects a deterministic jitter function (tests).
func (s *Store) SetJitter(fn func(int64) int64) { s.jitterFn = fn }
