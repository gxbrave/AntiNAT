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

// SSEHandler replays durable admin events from Last-Event-ID on the frozen
// /api/v1/events route. It polls the durable cursor rather than relying on an
// in-memory broadcast, so restart and reconnect behavior are identical
// (Story 4: durable Last-Event-ID, secret redaction). repair-1 H8 adds bounded
// subscriber capacity and a per-write deadline so a slow or stalled client
// cannot consume unbounded memory or hold the stream open forever.
type SSEHandler struct {
	Store EventStore
	// PollInterval is the store poll cadence (default 100ms).
	PollInterval time.Duration
	// Batch bounds each durable replay read (default 100, max 200).
	Batch int
	// MaxSubscribers bounds concurrent streams (default 64). A new stream
	// beyond the cap is refused with 503 UNAVAILABLE.
	MaxSubscribers int
	// WriteTimeout bounds each SSE write+flush so a slow reader fails closed
	// instead of buffering without limit (default 5s, 0 disables).
	WriteTimeout time.Duration

	subMu chan struct{}
}

func (h *SSEHandler) subscriberSlot() chan struct{} {
	if h.subMu == nil || cap(h.subMu) == 0 {
		return nil
	}
	return h.subMu
}

func (h *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	maxSubs := h.MaxSubscribers
	if maxSubs <= 0 {
		maxSubs = 64
	}
	writeTimeout := h.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 5 * time.Second
	}
	// Bounded subscriber gate (backpressure at the connection level).
	if h.subMu == nil {
		h.subMu = make(chan struct{}, maxSubs)
	}
	select {
	case h.subMu <- struct{}{}:
		defer func() { <-h.subMu }()
	default:
		writeSSEError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "too many event stream subscribers")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeSSEError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "event stream does not support flushing")
		return
	}
	controller := http.NewResponseController(w)
	setWriteDeadline := func() {
		if writeTimeout > 0 {
			_ = controller.SetWriteDeadline(time.Now().Add(writeTimeout))
		}
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
			setWriteDeadline()
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, sanitizeEventType(event.EventType), payload); err != nil {
				return
			}
			cursor = event.ID
		}
		setWriteDeadline()
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
