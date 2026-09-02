package store

// P15 repair-1: paginated/sorted/filtered node and forward list queries for
// the frozen listNodes/listForwards quota (PageParam/PageSizeParam/SortParam/
// FilterParam, NodePage/ForwardPage). Sort accepts a [+|-]field form
// (e.g. -created_at); filter accepts a single key=value clause (e.g.
// state=ONLINE). Unknown keys or malformed clauses are rejected with
// ErrInvalidListQuery so the API can return 400 rather than ignoring the
// caller's parameters. Total is computed over the same predicate so pages
// remain stable.

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidListQuery identifies a malformed sort/filter parameter.
var ErrInvalidListQuery = errors.New("store: invalid list query")

// ListQuery is one validated page request for a list endpoint.
type ListQuery struct {
	Page     int
	PageSize int
	Sort     string
	Filter   string
}

type listPredicate struct {
	where   string // column expression without the WHERE keyword; empty = none
	orderBy string
	args    []any
}

func (q ListQuery) predicate(node bool) (listPredicate, error) {
	p := listPredicate{orderBy: "id ASC"}
	// Sort: optional +/- prefix, then one of the declared sortable columns.
	if s := strings.TrimSpace(q.Sort); s != "" {
		desc := false
		switch s[0] {
		case '-':
			desc = true
			s = s[1:]
		case '+':
			s = s[1:]
		}
		col, ok := sortableColumn(node, s)
		if !ok || s == "" {
			return listPredicate{}, fmt.Errorf("%w: unsupported sort field %q", ErrInvalidListQuery, q.Sort)
		}
		dir := "ASC"
		if desc {
			dir = "DESC"
		}
		p.orderBy = col + " " + dir + ", id ASC"
	}
	// Filter: single key=value clause.
	if f := strings.TrimSpace(q.Filter); f != "" {
		eq := strings.IndexByte(f, '=')
		if eq <= 0 {
			return listPredicate{}, fmt.Errorf("%w: filter must be field=value", ErrInvalidListQuery)
		}
		key := strings.TrimSpace(f[:eq])
		value := strings.TrimSpace(f[eq+1:])
		if value == "" {
			return listPredicate{}, fmt.Errorf("%w: filter value must not be empty", ErrInvalidListQuery)
		}
		col, ok := filterableColumn(node, key)
		if !ok {
			return listPredicate{}, fmt.Errorf("%w: unsupported filter field %q", ErrInvalidListQuery, key)
		}
		p.args = append(p.args, value)
		p.where = col
	}
	return p, nil
}

func sortableColumn(node bool, field string) (string, bool) {
	if node {
		switch field {
		case "id", "name", "created_at", "control_state":
			return "nodes." + field, true
		}
		return "", false
	}
	switch field {
	case "id", "name", "created_at", "node_id", "protocol":
		return "forwards." + field, true
	}
	return "", false
}

func filterableColumn(node bool, key string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "state", "control_state":
		if node {
			return "nodes.control_state = ?", true
		}
		// Forward rows have no control_state column; the orthogonal runtime
		// snapshot is the accurate source (frozen ActivationStates).
		return `EXISTS(SELECT 1 FROM forward_runtime_status frs
		         WHERE frs.forward_id = forwards.id
		           AND json_extract(frs.snapshot_json, '$.snapshot.control_state') = ?)`, true
	case "name":
		if node {
			return "nodes.name = ?", true
		}
		return "forwards.name = ?", true
	case "node_id":
		if !node {
			return "forwards.node_id = ?", true
		}
	case "protocol":
		if !node {
			return "forwards.protocol = ?", true
		}
	}
	return "", false
}

// ListNodePage returns a stable predicate-bounded page of nodes and the total
// matching the filter.
func (s *Store) ListNodePage(q ListQuery) ([]Node, int, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 50
	}
	p, err := q.predicate(true)
	if err != nil {
		return nil, 0, err
	}
	whereClause := ""
	if p.where != "" {
		whereClause = " WHERE " + p.where
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes`+whereClause, p.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count node page: %w", err)
	}

	query := `SELECT id, name, current_connection_epoch, current_session_id,
	            control_state, revision, created_at, updated_at
	          FROM nodes` + whereClause + ` ORDER BY ` + p.orderBy + ` LIMIT ? OFFSET ?`
	args := append(append([]any{}, p.args...), q.PageSize, (q.Page-1)*q.PageSize)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list node page: %w", err)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.CurrentConnectionEpoch, &n.CurrentSessionID,
			&n.ControlState, &n.Revision, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("store: scan node page: %w", err)
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// ListForwardPage returns a stable predicate-bounded page of forwards and the
// total matching the filter.
func (s *Store) ListForwardPage(q ListQuery) ([]Forward, int, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 50
	}
	p, err := q.predicate(false)
	if err != nil {
		return nil, 0, err
	}
	whereClause := ""
	if p.where != "" {
		whereClause = " WHERE " + p.where
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM forwards`+whereClause, p.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count forward page: %w", err)
	}

	query := `SELECT id, node_id, name, protocol, current_activation_id,
	            revision, created_at, updated_at
	          FROM forwards` + whereClause + ` ORDER BY ` + p.orderBy + ` LIMIT ? OFFSET ?`
	args := append(append([]any{}, p.args...), q.PageSize, (q.Page-1)*q.PageSize)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list forward page: %w", err)
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		if err := rows.Scan(&f.ID, &f.NodeID, &f.Name, &f.Protocol, &f.CurrentActivationID,
			&f.Revision, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("store: scan forward page: %w", err)
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}
