package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// EventStore is the durable subset needed by the SSE handler.
type EventStore interface {
	AdminEventsAfter(cursor int64, limit int) ([]store.AdminEvent, error)
}

// SSEHandler replays durable admin events from Last-Event-ID. It polls the
// durable cursor rather than relying on an in-memory broadcast, so restart and
// reconnect behavior are identical.
type SSEHandler struct {
	Store        EventStore
	PollInterval time.Duration
	Batch        int
}

func (h SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeSSEError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "event stream is unavailable")
		return
	}
	cursor, err := parseEventCursor(r.Header.Get("Last-Event-ID"))
	if err != nil {
		writeSSEError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid Last-Event-ID")
		return
	}
	batch := h.Batch
	if batch <= 0 || batch > 200 {
		batch = 100
	}
	interval := h.PollInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeSSEError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "event stream does not support flushing")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		events, err := h.Store.AdminEventsAfter(cursor, batch)
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
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func parseEventCursor(raw string) (int64, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("invalid event cursor")
	}
	return n, nil
}

func sanitizeEventType(eventType string) string {
	if eventType == "" {
		return "message"
	}
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
	redactJSON(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func redactJSON(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "private_key") || lower == "value" {
				delete(v, key)
				continue
			}
			redactJSON(child)
		}
	case []any:
		for _, child := range v {
			redactJSON(child)
		}
	}
}

func writeSSEError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message, "request_id": "req"})
}
