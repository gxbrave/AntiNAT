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
	if s.eventSlots == nil {
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "event stream is unavailable")
		return
	}
	select {
	case s.eventSlots <- struct{}{}:
		defer func() { <-s.eventSlots }()
	default:
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "too many event stream subscribers")
		return
	}
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
	controller := http.NewResponseController(w)
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
			_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, sanitizeEventType(event.EventType), payload); err != nil {
				return
			}
			cursor = event.ID
		}
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
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
	value = redactEventValue(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func redactEventValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if secretFieldName(lower) {
				delete(v, key)
				continue
			}
			if s, ok := child.(string); ok && credentialLikeValue(s) {
				delete(v, key)
				continue
			}
			v[key] = redactEventValue(child)
		}
	case []any:
		for i, child := range v {
			v[i] = redactEventValue(child)
		}
	case string:
		if credentialLikeValue(v) {
			return "[REDACTED]"
		}
	}
	return value
}

// secretFieldName reports whether a lowercased object key belongs to a secret
// family by name (mirror of internal/controller/web/sse.go; kept in sync).
func secretFieldName(lower string) bool {
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(lower)
	return strings.Contains(compact, "token") || strings.Contains(compact, "secret") ||
		strings.Contains(compact, "password") || strings.Contains(compact, "passwd") ||
		strings.Contains(compact, "privatekey") || strings.Contains(compact, "apikey") ||
		strings.Contains(compact, "credential") || strings.Contains(compact, "authorization") ||
		strings.Contains(compact, "cookie")
}

// credentialLikeValue reports whether a string under a generic key is
// credential-shaped (mirror of internal/controller/web/sse.go; kept in sync).
func credentialLikeValue(v string) bool {
	if len(v) < 12 {
		return false
	}
	if structuredNonSecret(v) {
		return false
	}
	if len(v) >= 24 && !strings.ContainsAny(v, " \t") {
		return true
	}
	if hexTokenShape(v) || base64TokenShape(v) {
		return true
	}
	return highEntropyMixed(v)
}

func structuredNonSecret(v string) bool {
	if strings.Contains(v, "://") {
		return true // URL, never a credential
	}
	digits, letters := 0, 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letters++
		}
	}
	if letters <= 2 && digits*2 >= len(v) {
		return true
	}
	hexCount, sepCount := 0, 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			hexCount++
		case r == '-' || r == ':':
			sepCount++
		default:
			return false
		}
	}
	return hexCount >= 12 && sepCount >= 2
}

func hexTokenShape(v string) bool {
	if len(v) < 16 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func base64TokenShape(v string) bool {
	if len(v) < 12 {
		return false
	}
	aligned := len(v)%4 == 0
	hasPad := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '+', r == '/':
		case r == '=':
			hasPad = true
		default:
			return false
		}
	}
	return (hasPad && len(v) >= 12) || (aligned && len(v) >= 20)
}

func highEntropyMixed(v string) bool {
	if len(v) < 12 {
		return false
	}
	var upper, lower, digit, other bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, present := range []bool{upper, lower, digit, other} {
		if present {
			classes++
		}
	}
	return classes >= 3
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
