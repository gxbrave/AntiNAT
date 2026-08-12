package store

import (
	"fmt"
)

// AdminEvent is one durable, monotonically ordered SSE event. The id column
// is the Last-Event-ID cursor (docs/error-codes.md §7 and v0.8 §9.1: durable
// admin_events, never in-memory broadcast).
type AdminEvent struct {
	ID        int64
	EventType string
	Payload   string
	CreatedAt int64
}

// AppendAdminEvent appends a durable event and returns its monotonic id.
func (s *Store) AppendAdminEvent(eventType, payload string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
		eventType, payload, now(),
	)
	if err != nil {
		return 0, fmt.Errorf("store: append admin event: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: admin event id: %w", err)
	}
	return id, nil
}

// AdminEventsAfter returns up to limit events with id strictly greater than
// cursor, in ascending id order (an SSE resume from Last-Event-ID).
func (s *Store) AdminEventsAfter(cursor int64, limit int) ([]AdminEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, event_type, payload, created_at
		   FROM admin_events WHERE id > ? ORDER BY id ASC LIMIT ?`, cursor, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: query admin events: %w", err)
	}
	defer rows.Close()

	var events []AdminEvent
	for rows.Next() {
		var e AdminEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.Payload, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan admin event: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: admin events rows: %w", err)
	}
	return events, nil
}

// LastAdminEventID returns the highest durable event id (the SSE resume
// cursor), or 0 when the log is empty.
func (s *Store) LastAdminEventID() (int64, error) {
	var id int64
	if err := s.db.QueryRow(
		"SELECT COALESCE(MAX(id), 0) FROM admin_events",
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: last admin event id: %w", err)
	}
	return id, nil
}
