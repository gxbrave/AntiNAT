package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/metrics"
)

// TrafficDelta is a durable monotonic report from an Agent. Sequence is scoped
// to a Forward and is the idempotency fence for reconnect/redelivery.
// Completeness is explicit for new callers. FullyEffective/Legacy are retained
// as compatibility fields for older in-process producers; an all-zero report
// is rejected rather than silently classified.
type TrafficDelta struct {
	ForwardID             string
	Sequence              uint64
	Period                time.Time
	BytesIn               uint64
	BytesOut              uint64
	LegacyConnectionCount uint64
	FullyEffective        bool
	Legacy                bool
	Completeness          metrics.Completeness
}

type TrafficRollup struct {
	ForwardID             string
	Period                string
	BytesIn               uint64
	BytesOut              uint64
	LegacyConnectionCount uint64
	FullyEffective        bool
}

var (
	ErrTrafficDuplicate = errors.New("store: duplicate or out-of-order traffic delta")
	ErrTrafficInvalid   = errors.New("store: invalid traffic delta")

	ErrNavigationOrderConflict = errors.New("store: navigation order conflict")
)

func trafficCompleteness(delta TrafficDelta) (metrics.Completeness, error) {
	if delta.Completeness.Valid() {
		return delta.Completeness, nil
	}
	if delta.Legacy {
		return metrics.Legacy, nil
	}
	if delta.FullyEffective {
		return metrics.Complete, nil
	}
	return metrics.Unknown, ErrTrafficInvalid
}

// ApplyTrafficDelta atomically accepts a strictly newer sequence and updates
// its hourly rollup. Duplicate/out-of-order reports are ignored idempotently.
// Per-delta history is optional (SetTrafficDetailed), the hourly rollup remains
// durable regardless (matching the metrics accumulator
// TestAccumulatorDisabledDetailedHistoryStillRollsUp).
func (s *Store) ApplyTrafficDelta(delta TrafficDelta) (bool, error) {
	complete, err := trafficCompleteness(delta)
	if delta.ForwardID == "" || delta.Sequence == 0 || err != nil {
		return false, ErrTrafficInvalid
	}
	if delta.Period.IsZero() {
		delta.Period = time.Unix(s.currentUnix(), 0)
	}
	period := delta.Period.UTC().Truncate(time.Hour).Format(time.RFC3339)
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return false, fmt.Errorf("store: traffic delta connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return false, fmt.Errorf("store: begin traffic delta: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var last uint64
	err = conn.QueryRowContext(context.Background(), `SELECT sequence FROM traffic_ingest_cursors WHERE forward_id = ?`, delta.ForwardID).Scan(&last)
	if err == nil && delta.Sequence <= last {
		if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return false, fmt.Errorf("store: commit traffic duplicate: %w", err)
		}
		committed = true
		return false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("store: read traffic cursor: %w", err)
	}
	ts := s.currentUnix()
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO traffic_ingest_cursors (forward_id, sequence, updated_at)
		VALUES (?, ?, ?) ON CONFLICT(forward_id) DO UPDATE SET sequence=excluded.sequence, updated_at=excluded.updated_at`,
		delta.ForwardID, delta.Sequence, ts); err != nil {
		return false, fmt.Errorf("store: update traffic cursor: %w", err)
	}
	completeFlag := boolInt(complete == metrics.Complete)
	var detailed int
	if err := conn.QueryRowContext(context.Background(), `SELECT COALESCE(detailed, 0) FROM traffic_detail_settings WHERE forward_id = ?`, delta.ForwardID).Scan(&detailed); errors.Is(err, sql.ErrNoRows) {
		detailed = 0
	} else if err != nil {
		return false, fmt.Errorf("store: read traffic detail setting: %w", err)
	}
	if detailed != 0 {
		if _, err := conn.ExecContext(context.Background(), `INSERT INTO traffic_deltas
			(forward_id, sequence, period, bytes_in, bytes_out, legacy_connection_count, fully_effective, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			delta.ForwardID, delta.Sequence, period, delta.BytesIn, delta.BytesOut,
			delta.LegacyConnectionCount, completeFlag, ts); err != nil {
			return false, fmt.Errorf("store: insert traffic delta: %w", err)
		}
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO traffic_rollups
		(forward_id, period, bytes_in, bytes_out, legacy_connection_count, fully_effective, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(forward_id, period) DO UPDATE SET
		 bytes_in=traffic_rollups.bytes_in+excluded.bytes_in,
		 bytes_out=traffic_rollups.bytes_out+excluded.bytes_out,
		 legacy_connection_count=MAX(traffic_rollups.legacy_connection_count, excluded.legacy_connection_count),
		 fully_effective=traffic_rollups.fully_effective AND excluded.fully_effective,
		 updated_at=excluded.updated_at`,
		delta.ForwardID, period, delta.BytesIn, delta.BytesOut,
		delta.LegacyConnectionCount, completeFlag, ts); err != nil {
		return false, fmt.Errorf("store: update traffic rollup: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return false, fmt.Errorf("store: commit traffic delta: %w", err)
	}
	committed = true
	return true, nil
}

// SetTrafficDetailed controls optional per-delta retention for a Forward.
// Hourly rollups remain durable regardless of this setting.
func (s *Store) SetTrafficDetailed(forwardID string, enabled bool) error {
	if strings.TrimSpace(forwardID) == "" {
		return ErrTrafficInvalid
	}
	if _, err := s.GetForward(forwardID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO traffic_detail_settings(forward_id, detailed, updated_at)
		VALUES (?, ?, ?) ON CONFLICT(forward_id) DO UPDATE SET detailed=excluded.detailed, updated_at=excluded.updated_at`,
		forwardID, boolInt(enabled), s.currentUnix())
	if err != nil {
		return fmt.Errorf("store: set traffic detail: %w", err)
	}
	return nil
}

func (s *Store) TrafficDetailed(forwardID string) (bool, error) {
	var enabled int
	err := s.db.QueryRow(`SELECT detailed FROM traffic_detail_settings WHERE forward_id = ?`, forwardID).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: get traffic detail: %w", err)
	}
	return enabled != 0, nil
}

// ListTrafficDeltas returns bounded detailed history in sequence order.
func (s *Store) ListTrafficDeltas(forwardID string, limit, offset int) ([]TrafficDelta, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT forward_id, sequence, period, bytes_in, bytes_out,
		legacy_connection_count, fully_effective, created_at
		FROM traffic_deltas WHERE forward_id = ? ORDER BY sequence ASC LIMIT ? OFFSET ?`, forwardID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store: list traffic deltas: %w", err)
	}
	defer rows.Close()
	out := make([]TrafficDelta, 0)
	for rows.Next() {
		var d TrafficDelta
		var period string
		var complete, created int
		if err := rows.Scan(&d.ForwardID, &d.Sequence, &period, &d.BytesIn, &d.BytesOut, &d.LegacyConnectionCount, &complete, &created); err != nil {
			return nil, fmt.Errorf("store: scan traffic delta: %w", err)
		}
		d.Period, _ = time.Parse(time.RFC3339, period)
		d.Completeness = metrics.Legacy
		if complete != 0 {
			d.Completeness = metrics.Complete
			d.FullyEffective = true
		}
		_ = created
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListTrafficRollups returns bounded rollups in period order.
func (s *Store) ListTrafficRollups(forwardID string, limit, offset int) ([]TrafficRollup, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT forward_id, period, bytes_in, bytes_out, legacy_connection_count, fully_effective
		FROM traffic_rollups`
	args := make([]any, 0, 3)
	if forwardID != "" {
		query += ` WHERE forward_id = ?`
		args = append(args, forwardID)
	}
	query += ` ORDER BY period ASC, forward_id ASC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list traffic rollups: %w", err)
	}
	defer rows.Close()
	out := make([]TrafficRollup, 0)
	for rows.Next() {
		var r TrafficRollup
		var complete int
		if err := rows.Scan(&r.ForwardID, &r.Period, &r.BytesIn, &r.BytesOut, &r.LegacyConnectionCount, &complete); err != nil {
			return nil, fmt.Errorf("store: scan traffic rollup: %w", err)
		}
		r.FullyEffective = complete != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: traffic rollup rows: %w", err)
	}
	return out, nil
}

func (s *Store) TrafficRollupCount(forwardID string) (int, error) {
	var n int
	query := `SELECT COUNT(*) FROM traffic_rollups`
	args := []any{}
	if forwardID != "" {
		query += ` WHERE forward_id = ?`
		args = append(args, forwardID)
	}
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count traffic rollups: %w", err)
	}
	return n, nil
}

// APIOperation is the durable status surface for asynchronous API actions.
type APIOperation struct {
	ID                     string
	Kind                   string
	NodeID                 string
	ForwardID              string
	State                  string
	Detail                 string
	RemoteCleanupConfirmed bool
	CreatedAt              int64
	UpdatedAt              int64
	CompletedAt            int64
}

func (s *Store) CreateAPIOperation(op APIOperation) (APIOperation, error) {
	if op.ID == "" || op.Kind == "" || op.State == "" {
		return APIOperation{}, ErrTrafficInvalid
	}
	ts := s.currentUnix()
	_, err := s.db.Exec(`INSERT INTO api_operations
		(id, kind, node_id, forward_id, state, detail, remote_cleanup_confirmed, created_at, updated_at, completed_at)
		VALUES (?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, ?, NULLIF(?, 0))`,
		op.ID, op.Kind, op.NodeID, op.ForwardID, op.State, op.Detail, boolInt(op.RemoteCleanupConfirmed), ts, ts, op.CompletedAt)
	if err != nil {
		return APIOperation{}, fmt.Errorf("store: create api operation: %w", err)
	}
	return s.GetAPIOperation(op.ID)
}

func (s *Store) GetAPIOperation(id string) (APIOperation, error) {
	var op APIOperation
	var nodeID, forwardID sql.NullString
	var confirmed int
	var completed sql.NullInt64
	err := s.db.QueryRow(`SELECT id, kind, node_id, forward_id, state, detail, remote_cleanup_confirmed, created_at, updated_at, completed_at
		FROM api_operations WHERE id = ?`, id).Scan(&op.ID, &op.Kind, &nodeID, &forwardID, &op.State, &op.Detail, &confirmed, &op.CreatedAt, &op.UpdatedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return APIOperation{}, ErrNotFound
	}
	if err != nil {
		return APIOperation{}, fmt.Errorf("store: get api operation: %w", err)
	}
	op.NodeID, op.ForwardID = nodeID.String, forwardID.String
	op.RemoteCleanupConfirmed, op.CompletedAt = confirmed != 0, completed.Int64
	return op, nil
}

func (s *Store) UpdateAPIOperation(id, state, detail string, confirmed bool) error {
	res, err := s.db.Exec(`UPDATE api_operations SET state=?, detail=?, remote_cleanup_confirmed=?, updated_at=?, completed_at=CASE WHEN ? IN ('COMPLETED','FAILED') THEN ? ELSE completed_at END WHERE id=?`,
		state, detail, boolInt(confirmed), s.currentUnix(), state, s.currentUnix(), id)
	if err != nil {
		return fmt.Errorf("store: update api operation: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// UpdateNodeNameCAS applies a revision-checked node rename.
func (s *Store) UpdateNodeNameCAS(id string, expected uint64, name string) (Node, error) {
	if strings.TrimSpace(name) == "" {
		return Node{}, ErrTrafficInvalid
	}
	res, err := s.db.Exec(`UPDATE nodes SET name=?, revision=revision+1, updated_at=? WHERE id=? AND revision=?`, name, s.currentUnix(), id, expected)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return Node{}, ErrNavigationOrderConflict
		}
		return Node{}, fmt.Errorf("store: update node name: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, getErr := s.GetNode(id); errors.Is(getErr, ErrNodeNotFound) {
			return Node{}, ErrNodeNotFound
		}
		return Node{}, ErrCASConflict
	}
	return s.GetNode(id)
}

// TraversalDefaults is the persisted per-node TCP/UDP default selection.
type TraversalDefaults struct {
	NodeID      string
	TCPStrategy string
	UDPStrategy string
	Revision    uint64
	UpdatedAt   int64
}

func (s *Store) GetTraversalDefaults(nodeID string) (TraversalDefaults, error) {
	var d TraversalDefaults
	err := s.db.QueryRow(`SELECT node_id,tcp_strategy,udp_strategy,revision,updated_at FROM node_traversal_defaults WHERE node_id=?`, nodeID).
		Scan(&d.NodeID, &d.TCPStrategy, &d.UDPStrategy, &d.Revision, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TraversalDefaults{NodeID: nodeID, Revision: 0}, nil
	}
	if err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: get traversal defaults: %w", err)
	}
	return d, nil
}

func (s *Store) PutTraversalDefaults(nodeID, tcp, udp string, expected uint64) (TraversalDefaults, error) {
	node, err := s.GetNode(nodeID)
	if err != nil {
		return TraversalDefaults{}, err
	}
	if tcp != "" {
		if _, err := parseStrategy(tcp); err != nil {
			return TraversalDefaults{}, fmt.Errorf("%w: tcp_strategy: %v", ErrTrafficInvalid, err)
		}
	}
	if udp != "" {
		if _, err := parseStrategy(udp); err != nil {
			return TraversalDefaults{}, fmt.Errorf("%w: udp_strategy: %v", ErrTrafficInvalid, err)
		}
	}
	// The If-Match axis is the NODE revision (the handler derives expected from
	// etagFor(node.Revision)). The defaults row may legitimately lag the node
	// revision after any other node.rev bump (rename UpdateNodeNameCAS, agent
	// reconnect AcquireControlOwner both bump nodes.revision), so the node
	// revision is the only valid baseline. Comparing expected against the
	// defaults-row revision here would reproduce the permanent-412 drift: the
	// first PUT succeeds, then any rename/reconnect bump makes every later PUT
	// carrying the current node ETag fail forever (repair-2 P1-B).
	if expected != node.Revision {
		return TraversalDefaults{}, ErrCASConflict
	}
	next := expected + 1
	now := s.currentUnix()
	// One BEGIN IMMEDIATE transaction contains the defaults upsert AND the
	// parent node revision bump. The durable CAS gate is the conditional UPDATE
	// on nodes.revision (RowsAffected=0 -> ErrCASConflict -> rollback): it is
	// the only statement whose WHERE compares the If-Match axis. The defaults
	// upsert deliberately has NO revision guard — an ON CONFLICT WHERE comparing
	// node_traversal_defaults.revision (the pre-fix form) turns an out-of-sync
	// defaults row into the permanent-412 defect replayed. The defaults row is
	// written lockstep (revision = next), keeping it aligned with the node.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: traversal defaults conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: begin traversal defaults: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO node_traversal_defaults(node_id,tcp_strategy,udp_strategy,revision,updated_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(node_id) DO UPDATE SET tcp_strategy=excluded.tcp_strategy,udp_strategy=excluded.udp_strategy,revision=excluded.revision,updated_at=excluded.updated_at`,
		nodeID, tcp, udp, next, now); err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: put traversal defaults: %w", err)
	}
	upd, err := conn.ExecContext(context.Background(),
		`UPDATE nodes SET revision = ?, updated_at = ? WHERE id = ? AND revision = ?`,
		next, now, nodeID, expected)
	if err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: bump traversal defaults node revision: %w", err)
	}
	if n, err := upd.RowsAffected(); err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: traversal defaults node revision rows: %w", err)
	} else if n != 1 {
		return TraversalDefaults{}, ErrCASConflict
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return TraversalDefaults{}, fmt.Errorf("store: commit traversal defaults: %w", err)
	}
	committed = true
	return TraversalDefaults{NodeID: nodeID, TCPStrategy: tcp, UDPStrategy: udp, Revision: next, UpdatedAt: now}, nil
}

func parseStrategy(value string) (string, error) {
	valid := map[string]bool{"direct-v4": true, "manual-static-v4": true, "explicit-gateway": true, "stun-only": true, "auto": true}
	if !valid[value] {
		return "", fmt.Errorf("store: unknown traversal strategy %q", value)
	}
	return value, nil
}

// NavigationCategory and NavigationItem are durable operator navigation rows.
type NavigationCategory struct {
	ID, Name             string
	OrderIndex           int
	Revision             uint64
	CreatedAt, UpdatedAt int64
}
type NavigationItem struct {
	ID, Name, Description, Protocol, CategoryID, ForwardID string
	OrderIndex                                             int
	Revision                                               uint64
	CreatedAt, UpdatedAt                                   int64
}

type NavigationOrder struct {
	CategoryIDs, ItemIDs []string
	Revision             uint64
	UpdatedAt            int64
}

func (s *Store) ListNavigationCategories() ([]NavigationCategory, error) {
	rows, err := s.db.Query(`SELECT id,name,order_index,revision,created_at,updated_at FROM navigation_categories ORDER BY order_index,id`)
	if err != nil {
		return nil, fmt.Errorf("store: list navigation categories: %w", err)
	}
	defer rows.Close()
	out := make([]NavigationCategory, 0)
	for rows.Next() {
		var c NavigationCategory
		if err := rows.Scan(&c.ID, &c.Name, &c.OrderIndex, &c.Revision, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) GetNavigationCategory(id string) (NavigationCategory, error) {
	var c NavigationCategory
	err := s.db.QueryRow(`SELECT id,name,order_index,revision,created_at,updated_at FROM navigation_categories WHERE id=?`, id).Scan(&c.ID, &c.Name, &c.OrderIndex, &c.Revision, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NavigationCategory{}, ErrNotFound
	}
	if err != nil {
		return NavigationCategory{}, err
	}
	return c, nil
}

// CreateNavigationCategoryIdempotent atomically persists a navigation category
// and its idempotency response under BEGIN IMMEDIATE (repair-1 H4), so the
// API's Idempotency-Key is a durable replayed/conflict authority rather than a
// format-only check. A replay returns the stored response unchanged; a
// same-key different-request reuse is ErrIdempotencyConflict.
func (s *Store) CreateNavigationCategoryIdempotent(ctx context.Context, c NavigationCategory, rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	if c.ID == "" || strings.TrimSpace(c.Name) == "" {
		return IdempotencyRecord{}, false, ErrTrafficInvalid
	}
	if err := s.checkWriteCapacity(); err != nil {
		return IdempotencyRecord{}, false, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: nav category conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: begin nav category: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	existing, replayed, conflict, err := replayOrInsertIdempotency(ctx, conn, rec)
	if err != nil {
		return IdempotencyRecord{}, false, err
	}
	if conflict {
		return IdempotencyRecord{}, false, ErrIdempotencyConflict
	}
	if replayed {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: commit nav category replay: %w", err)
		}
		committed = true
		return existing, true, nil
	}
	if c.Revision == 0 {
		c.Revision = 1
	}
	if c.OrderIndex < 0 {
		return IdempotencyRecord{}, false, ErrNavigationOrderConflict
	}
	var existsOrder int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM navigation_categories WHERE order_index=?)`, c.OrderIndex).Scan(&existsOrder); err != nil {
		return IdempotencyRecord{}, false, err
	}
	if existsOrder != 0 {
		return IdempotencyRecord{}, false, ErrNavigationOrderConflict
	}
	ts := now()
	if _, err := conn.ExecContext(ctx, `INSERT INTO navigation_categories(id,name,order_index,revision,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		c.ID, c.Name, c.OrderIndex, c.Revision, ts, ts); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return IdempotencyRecord{}, false, ErrNavigationOrderConflict
		}
		return IdempotencyRecord{}, false, err
	}
	if rec.ExpiresAt == 0 {
		rec.ExpiresAt = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	rec.CreatedAt = ts
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO api_idempotency_keys (key, route, principal, request_hash, response_status, response_body, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Key, rec.Route, rec.Principal, rec.RequestHash, rec.ResponseStatus, rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: nav category idempotency insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: commit nav category: %w", err)
	}
	committed = true
	return rec, false, nil
}

// CreateNavigationItemIdempotent is the navigation-items counterpart of
// CreateNavigationCategoryIdempotent (repair-1 H4).
func (s *Store) CreateNavigationItemIdempotent(ctx context.Context, i NavigationItem, rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rec.Key == "" {
		return IdempotencyRecord{}, false, errors.New("store: empty idempotency key")
	}
	if i.ID == "" || i.Name == "" || i.CategoryID == "" || i.ForwardID == "" {
		return IdempotencyRecord{}, false, ErrTrafficInvalid
	}
	if err := s.checkWriteCapacity(); err != nil {
		return IdempotencyRecord{}, false, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: nav item conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: begin nav item: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	existing, replayed, conflict, err := replayOrInsertIdempotency(ctx, conn, rec)
	if err != nil {
		return IdempotencyRecord{}, false, err
	}
	if conflict {
		return IdempotencyRecord{}, false, ErrIdempotencyConflict
	}
	if replayed {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return IdempotencyRecord{}, false, fmt.Errorf("store: commit nav item replay: %w", err)
		}
		committed = true
		return existing, true, nil
	}
	if i.Revision == 0 {
		i.Revision = 1
	}
	if i.OrderIndex < 0 {
		return IdempotencyRecord{}, false, ErrNavigationOrderConflict
	}
	var existsOrder int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM navigation_items WHERE category_id=? AND order_index=?)`, i.CategoryID, i.OrderIndex).Scan(&existsOrder); err != nil {
		return IdempotencyRecord{}, false, err
	}
	if existsOrder != 0 {
		return IdempotencyRecord{}, false, ErrNavigationOrderConflict
	}
	var fwdExists int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM forwards WHERE id=?)`, i.ForwardID).Scan(&fwdExists); err != nil {
		return IdempotencyRecord{}, false, err
	}
	if fwdExists == 0 {
		return IdempotencyRecord{}, false, ErrForwardNotFound
	}
	ts := now()
	if _, err := conn.ExecContext(ctx, `INSERT INTO navigation_items(id,name,description,protocol,category_id,forward_id,order_index,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		i.ID, i.Name, i.Description, i.Protocol, i.CategoryID, i.ForwardID, i.OrderIndex, i.Revision, ts, ts); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "FOREIGN KEY") {
			return IdempotencyRecord{}, false, ErrNavigationOrderConflict
		}
		return IdempotencyRecord{}, false, err
	}
	if rec.ExpiresAt == 0 {
		rec.ExpiresAt = ts + int64(IdempotencyKeyTTL/time.Second)
	}
	rec.CreatedAt = ts
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO api_idempotency_keys (key, route, principal, request_hash, response_status, response_body, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Key, rec.Route, rec.Principal, rec.RequestHash, rec.ResponseStatus, rec.ResponseBody, rec.CreatedAt, rec.ExpiresAt); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: nav item idempotency insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return IdempotencyRecord{}, false, fmt.Errorf("store: commit nav item: %w", err)
	}
	committed = true
	return rec, false, nil
}

// replayOrInsertIdempotency runs the shared idempotency read/replay/expire
// logic inside an already-open BEGIN IMMEDIATE transaction. It returns the
// stored replay record, whether to replay, whether this is a hard conflict,
// or a storage error. conflict=true is separate because Go cannot distinguish
// "store response then return error" from a plain return.
func replayOrInsertIdempotency(ctx context.Context, conn *sql.Conn, rec IdempotencyRecord) (IdempotencyRecord, bool, bool, error) {
	ts := now()
	var existing IdempotencyRecord
	err := conn.QueryRowContext(ctx,
		`SELECT key, route, principal, request_hash, response_status, response_body, created_at, expires_at
		   FROM api_idempotency_keys WHERE key = ?`, rec.Key,
	).Scan(&existing.Key, &existing.Route, &existing.Principal, &existing.RequestHash,
		&existing.ResponseStatus, &existing.ResponseBody, &existing.CreatedAt, &existing.ExpiresAt)
	switch {
	case err == nil && existing.ExpiresAt > ts && existing.Route == rec.Route &&
		existing.Principal == rec.Principal && existing.RequestHash == rec.RequestHash:
		return existing, true, false, nil
	case err == nil && existing.ExpiresAt > ts:
		return IdempotencyRecord{}, false, true, nil
	case err == nil:
		if _, err := conn.ExecContext(ctx, `DELETE FROM api_idempotency_keys WHERE key = ?`, rec.Key); err != nil {
			return IdempotencyRecord{}, false, false, fmt.Errorf("store: expire idempotency delete: %w", err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"IDEMPOTENCY_KEY_EXPIRED", fmt.Sprintf(`{"key":%q,"route":%q}`, rec.Key, rec.Route), ts); err != nil {
			return IdempotencyRecord{}, false, false, fmt.Errorf("store: nav idempotency expiry audit: %w", err)
		}
		return IdempotencyRecord{}, false, false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return IdempotencyRecord{}, false, false, fmt.Errorf("store: read idempotency: %w", err)
	default:
		return IdempotencyRecord{}, false, false, nil
	}
}

func (s *Store) CreateNavigationCategory(c NavigationCategory) (NavigationCategory, error) {
	if c.ID == "" || strings.TrimSpace(c.Name) == "" {
		return NavigationCategory{}, ErrTrafficInvalid
	}
	if c.Revision == 0 {
		c.Revision = 1
	}
	now := s.currentUnix()
	if c.OrderIndex < 0 {
		return NavigationCategory{}, ErrNavigationOrderConflict
	}
	var exists int
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM navigation_categories WHERE order_index=?)`, c.OrderIndex).Scan(&exists); err != nil {
		return NavigationCategory{}, err
	}
	if exists != 0 {
		return NavigationCategory{}, ErrNavigationOrderConflict
	}
	_, err := s.db.Exec(`INSERT INTO navigation_categories(id,name,order_index,revision,created_at,updated_at) VALUES(?,?,?,?,?,?)`, c.ID, c.Name, c.OrderIndex, c.Revision, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return NavigationCategory{}, ErrNavigationOrderConflict
		}
		return NavigationCategory{}, err
	}
	return s.GetNavigationCategory(c.ID)
}
func (s *Store) UpdateNavigationCategoryCAS(id string, expected uint64, name string, order int) (NavigationCategory, error) {
	if _, err := s.GetNavigationCategory(id); err != nil {
		return NavigationCategory{}, err
	}
	if order < 0 {
		return NavigationCategory{}, ErrNavigationOrderConflict
	}
	// repair-2 P2-C: the EXISTS pre-check and the UPDATE were two separate
	// statements, so two concurrent writers could BOTH pass the pre-check and
	// then race the same order_index on the UPDATE. Serialize them under
	// BEGIN IMMEDIATE: the loser's pre-check runs after the winner commits and
	// sees the winning row, so it maps to ErrNavigationOrderConflict instead of
	// racing a duplicate. The UNIQUE-error mapping is the defensive belt: a
	// duplicate row surfaced by any path stays a navigation-order conflict
	// (409), never a raw error (500).
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return NavigationCategory{}, fmt.Errorf("store: navigation category conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return NavigationCategory{}, fmt.Errorf("store: begin navigation category update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var exists int
	if err := conn.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM navigation_categories WHERE order_index=? AND id<>?)`, order, id).Scan(&exists); err != nil {
		return NavigationCategory{}, err
	}
	if exists != 0 {
		return NavigationCategory{}, ErrNavigationOrderConflict
	}
	res, err := conn.ExecContext(context.Background(),
		`UPDATE navigation_categories SET name=?,order_index=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		name, order, s.currentUnix(), id, expected)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return NavigationCategory{}, ErrNavigationOrderConflict
		}
		return NavigationCategory{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return NavigationCategory{}, ErrCASConflict
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return NavigationCategory{}, fmt.Errorf("store: commit navigation category update: %w", err)
	}
	committed = true
	return s.GetNavigationCategory(id)
}
func (s *Store) DeleteNavigationCategoryCAS(id string, expected uint64) error {
	res, err := s.db.Exec(`DELETE FROM navigation_categories WHERE id=? AND revision=?`, id, expected)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, e := s.GetNavigationCategory(id); errors.Is(e, ErrNotFound) {
			return ErrNotFound
		}
		return ErrCASConflict
	}
	return nil
}

func (s *Store) ListNavigationItems() ([]NavigationItem, error) {
	rows, err := s.db.Query(`SELECT id,name,description,protocol,category_id,forward_id,order_index,revision,created_at,updated_at FROM navigation_items ORDER BY category_id,order_index,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]NavigationItem, 0)
	for rows.Next() {
		var i NavigationItem
		if err := rows.Scan(&i.ID, &i.Name, &i.Description, &i.Protocol, &i.CategoryID, &i.ForwardID, &i.OrderIndex, &i.Revision, &i.CreatedAt, &i.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
func (s *Store) GetNavigationItem(id string) (NavigationItem, error) {
	var i NavigationItem
	err := s.db.QueryRow(`SELECT id,name,description,protocol,category_id,forward_id,order_index,revision,created_at,updated_at FROM navigation_items WHERE id=?`, id).Scan(&i.ID, &i.Name, &i.Description, &i.Protocol, &i.CategoryID, &i.ForwardID, &i.OrderIndex, &i.Revision, &i.CreatedAt, &i.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NavigationItem{}, ErrNotFound
	}
	if err != nil {
		return NavigationItem{}, err
	}
	return i, nil
}
func (s *Store) CreateNavigationItem(i NavigationItem) (NavigationItem, error) {
	if i.ID == "" || i.Name == "" || i.CategoryID == "" || i.ForwardID == "" {
		return NavigationItem{}, ErrTrafficInvalid
	}
	if i.Revision == 0 {
		i.Revision = 1
	}
	if i.OrderIndex < 0 {
		return NavigationItem{}, ErrNavigationOrderConflict
	}
	var exists int
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM navigation_items WHERE category_id=? AND order_index=?)`, i.CategoryID, i.OrderIndex).Scan(&exists); err != nil {
		return NavigationItem{}, err
	}
	if exists != 0 {
		return NavigationItem{}, ErrNavigationOrderConflict
	}
	now := s.currentUnix()
	_, err := s.db.Exec(`INSERT INTO navigation_items(id,name,description,protocol,category_id,forward_id,order_index,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, i.ID, i.Name, i.Description, i.Protocol, i.CategoryID, i.ForwardID, i.OrderIndex, i.Revision, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "FOREIGN KEY") {
			return NavigationItem{}, ErrNavigationOrderConflict
		}
		return NavigationItem{}, err
	}
	return s.GetNavigationItem(i.ID)
}
func (s *Store) UpdateNavigationItemCAS(i NavigationItem, expected uint64) (NavigationItem, error) {
	if _, err := s.GetNavigationItem(i.ID); err != nil {
		return NavigationItem{}, err
	}
	if i.Name == "" || i.CategoryID == "" || i.ForwardID == "" || i.OrderIndex < 0 {
		return NavigationItem{}, ErrTrafficInvalid
	}
	// repair-2 P2-C: same pre-check/UPDATE race as UpdateNavigationCategoryCAS;
	// serialize under BEGIN IMMEDIATE so a concurrent writer claiming the same
	// (category_id, order_index) maps to ErrNavigationOrderConflict, never a raw
	// error (500). The UNIQUE-error mapping is the defensive belt.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return NavigationItem{}, fmt.Errorf("store: navigation item conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return NavigationItem{}, fmt.Errorf("store: begin navigation item update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var exists int
	if err := conn.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM navigation_items WHERE category_id=? AND order_index=? AND id<>?)`, i.CategoryID, i.OrderIndex, i.ID).Scan(&exists); err != nil {
		return NavigationItem{}, err
	}
	if exists != 0 {
		return NavigationItem{}, ErrNavigationOrderConflict
	}
	res, err := conn.ExecContext(context.Background(),
		`UPDATE navigation_items SET name=?,description=?,protocol=?,category_id=?,forward_id=?,order_index=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		i.Name, i.Description, i.Protocol, i.CategoryID, i.ForwardID, i.OrderIndex, s.currentUnix(), i.ID, expected)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return NavigationItem{}, ErrNavigationOrderConflict
		}
		return NavigationItem{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return NavigationItem{}, ErrCASConflict
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return NavigationItem{}, fmt.Errorf("store: commit navigation item update: %w", err)
	}
	committed = true
	return s.GetNavigationItem(i.ID)
}
func (s *Store) DeleteNavigationItemCAS(id string, expected uint64) error {
	res, err := s.db.Exec(`DELETE FROM navigation_items WHERE id=? AND revision=?`, id, expected)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, e := s.GetNavigationItem(id); errors.Is(e, ErrNotFound) {
			return ErrNotFound
		}
		return ErrCASConflict
	}
	return nil
}

func (s *Store) GetNavigationOrder() (NavigationOrder, error) {
	var cats, items string
	var o NavigationOrder
	err := s.db.QueryRow(`SELECT category_ids,item_ids,revision,updated_at FROM navigation_order WHERE id=1`).Scan(&cats, &items, &o.Revision, &o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NavigationOrder{Revision: 0}, nil
	}
	if err != nil {
		return NavigationOrder{}, err
	}
	if err := json.Unmarshal([]byte(cats), &o.CategoryIDs); err != nil {
		return NavigationOrder{}, err
	}
	if err := json.Unmarshal([]byte(items), &o.ItemIDs); err != nil {
		return NavigationOrder{}, err
	}
	return o, nil
}
func (s *Store) PutNavigationOrder(expected uint64, order NavigationOrder) (NavigationOrder, error) {
	if order.Revision == 0 {
		order.Revision = expected + 1
	}
	current, err := s.GetNavigationOrder()
	if err != nil {
		return NavigationOrder{}, err
	}
	if current.Revision != expected {
		return NavigationOrder{}, ErrCASConflict
	}
	if err := validateIDs(s.db, "navigation_categories", order.CategoryIDs); err != nil {
		return NavigationOrder{}, err
	}
	if err := validateIDs(s.db, "navigation_items", order.ItemIDs); err != nil {
		return NavigationOrder{}, err
	}
	cats, _ := json.Marshal(order.CategoryIDs)
	items, _ := json.Marshal(order.ItemIDs)
	now := s.currentUnix()
	// repair-1 H6: the upsert is conditional on the persisted revision so two
	// concurrent writers cannot both pass the read and lose one update; the
	// loser fails RowsAffected=0 and maps to ErrCASConflict (412 in the API).
	res, err := s.db.Exec(`INSERT INTO navigation_order(id,category_ids,item_ids,revision,updated_at) VALUES(1,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET category_ids=excluded.category_ids,item_ids=excluded.item_ids,revision=excluded.revision,updated_at=excluded.updated_at
		WHERE navigation_order.revision = ?`, string(cats), string(items), expected+1, now, expected)
	if err != nil {
		return NavigationOrder{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return NavigationOrder{}, ErrCASConflict
	}
	order.Revision = expected + 1
	order.UpdatedAt = now
	return order, nil
}
func validateIDs(db *sql.DB, table string, ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			return ErrNavigationOrderConflict
		}
		seen[id] = true
		var n int
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=?)`, id).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrNavigationOrderConflict
		}
	}
	return nil
}

// SettingsRecord stores the JSON representation of the frozen Settings shape.
type SettingsRecord struct {
	JSON      string
	Revision  uint64
	UpdatedAt int64
}

func (s *Store) GetSettingsRecord() (SettingsRecord, error) {
	var r SettingsRecord
	err := s.db.QueryRow(`SELECT settings_json,revision,updated_at FROM api_settings WHERE id=1`).Scan(&r.JSON, &r.Revision, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SettingsRecord{JSON: `{}`, Revision: 0}, nil
	}
	if err != nil {
		return SettingsRecord{}, err
	}
	return r, nil
}
func (s *Store) PutSettingsRecord(expected uint64, raw string) (SettingsRecord, error) {
	if !json.Valid([]byte(raw)) {
		return SettingsRecord{}, ErrTrafficInvalid
	}
	current, err := s.GetSettingsRecord()
	if err != nil {
		return SettingsRecord{}, err
	}
	if current.Revision != expected {
		return SettingsRecord{}, ErrCASConflict
	}
	now := s.currentUnix()
	// repair-1 H6: conditional compare-and-set on the persisted revision so a
	// concurrent writer cannot lose an update after the read.
	res, err := s.db.Exec(`INSERT INTO api_settings(id,settings_json,revision,updated_at) VALUES(1,?,?,?)
		ON CONFLICT(id) DO UPDATE SET settings_json=excluded.settings_json,revision=excluded.revision,updated_at=excluded.updated_at
		WHERE api_settings.revision = ?`, raw, expected+1, now, expected)
	if err != nil {
		return SettingsRecord{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return SettingsRecord{}, ErrCASConflict
	}
	return SettingsRecord{JSON: raw, Revision: expected + 1, UpdatedAt: now}, nil
}

// DeploymentProfile is structured JSON only; command rendering belongs to P17.
type DeploymentProfile struct {
	NodeID               string
	JSON                 string
	Revision             uint64
	CreatedAt, UpdatedAt int64
}

func (s *Store) GetDeploymentProfile(nodeID string) (DeploymentProfile, error) {
	var p DeploymentProfile
	err := s.db.QueryRow(`SELECT node_id,profile_json,revision,created_at,updated_at FROM node_deployment_profiles WHERE node_id=?`, nodeID).Scan(&p.NodeID, &p.JSON, &p.Revision, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeploymentProfile{NodeID: nodeID}, ErrNotFound
	}
	if err != nil {
		return DeploymentProfile{}, err
	}
	return p, nil
}

// PutDeploymentProfile is retained as the public P15 store seam; P17 owns
// the strict structured validation and atomic CAS implementation it delegates
// to. A profile is never accepted as arbitrary JSON.
func (s *Store) PutDeploymentProfile(nodeID string, expected uint64, raw string) (DeploymentProfile, error) {
	return s.putDeploymentProfileCAS(nodeID, expected, raw)
}

// AuditEntry is the safe API-facing audit projection.
type AuditEntry struct {
	ID        int64
	Event     string
	Target    string
	Detail    string
	CreatedAt int64
}

func (s *Store) AppendAudit(actor, action, target, detail string) error {
	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	_, err := s.db.Exec(`INSERT INTO admin_audit_logs(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)`, actor, action, target, detail, s.currentUnix())
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}
func (s *Store) ListAudit(afterID int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,action,COALESCE(target,''),COALESCE(detail,''),created_at FROM admin_audit_logs WHERE id>? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Event, &e.Target, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func validateP15MetricsObjects(q schemaQueryer) error {
	for _, table := range []string{"traffic_ingest_cursors", "traffic_deltas", "traffic_rollups", "traffic_detail_settings", "navigation_categories", "navigation_items", "node_traversal_defaults", "node_deployment_profiles", "api_operations", "api_settings", "navigation_order"} {
		var got string
		if err := q.QueryRow("SELECT type FROM sqlite_master WHERE name = ?", table).Scan(&got); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: migration 9 missing required object %s", ErrNotMigrated, table)
		} else if err != nil {
			return fmt.Errorf("store: inspect migration 9 object %s: %w", table, err)
		} else if got != "table" {
			return fmt.Errorf("%w: migration 9 object %s has type %q", ErrNotMigrated, table, got)
		}
	}
	return nil
}
