package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	cursor := int64(0)
	if raw := strings.TrimSpace(r.Header.Get("Last-Event-ID")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid Last-Event-ID")
			return
		}
		cursor = parsed
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "event stream does not support flushing")
		return
	}
	for {
		events, err := s.store.AdminEventsAfter(cursor, 100)
		if err != nil {
			return
		}
		for _, event := range events {
			if event.ID <= cursor {
				continue
			}
			payload := redactEventPayload(event.Payload)
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, sanitizeEventType(event.EventType), payload); err != nil {
				return
			}
			cursor = event.ID
		}
		flusher.Flush()
		if len(events) > 0 {
			continue
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func sanitizeEventType(eventType string) string {
	var b strings.Builder
	for _, r := range eventType {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "message"
	}
	return b.String()
}

func redactEventPayload(raw string) string {
	var value any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return "{}"
	}
	redactEventValue(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func redactEventValue(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "private_key") || lower == "value" {
				delete(v, key)
				continue
			}
			redactEventValue(child)
		}
	case []any:
		for _, child := range v {
			redactEventValue(child)
		}
	}
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
	page, size, ok := parsePage(w, r)
	if !ok {
		return
	}
	rows, err := s.store.ListTrafficRollups("", size, (page-1)*size)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "traffic lookup failed")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, map[string]any{
			"forward_id": row.ForwardID, "period": row.Period,
			"bytes_in": row.BytesIn, "bytes_out": row.BytesOut,
			"legacy_connection_count": row.LegacyConnectionCount,
			"fully_effective":         row.FullyEffective,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
	_, size, ok := parsePage(w, r)
	if !ok {
		return
	}
	cursor := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "INVALID_PAGINATION", "invalid cursor")
			return
		}
		cursor = parsed
	}
	rows, err := s.store.ListAudit(cursor, size)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "audit lookup failed")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	next := cursor
	for _, row := range rows {
		detail := json.RawMessage(row.Detail)
		if row.Detail == "" {
			detail = json.RawMessage(`{}`)
		}
		items = append(items, map[string]any{"id": row.ID, "event": row.Event, "detail": detail, "created_at": operationTime(row.CreatedAt)})
		if row.ID > next {
			next = row.ID
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": strconv.FormatInt(next, 10)})
}

func parsePage(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	page, size := 1, 50
	q := r.URL.Query()
	if raw := q.Get("page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "INVALID_PAGINATION", "invalid page")
			return 0, 0, false
		}
		page = n
	}
	if raw := q.Get("page_size"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeError(w, http.StatusBadRequest, "INVALID_PAGINATION", "invalid page_size")
			return 0, 0, false
		}
		size = n
	}
	return page, size, true
}

// parseListQuery validates the frozen listNodes/listForwards query parameters
// (page 1..N, page_size 1..200, sort [+|-]field, filter field=value) and
// returns a typed store.ListQuery. The store owns the sort/filter grammar;
// this layer only enforces the integer bounds up front so a malformed page
// never reaches SQL.
func parseListQuery(w http.ResponseWriter, r *http.Request) (store.ListQuery, bool) {
	page, size, ok := parsePage(w, r)
	if !ok {
		return store.ListQuery{}, false
	}
	q := r.URL.Query()
	return store.ListQuery{
		Page:     page,
		PageSize: size,
		Sort:     strings.TrimSpace(q.Get("sort")),
		Filter:   strings.TrimSpace(q.Get("filter")),
	}, true
}
