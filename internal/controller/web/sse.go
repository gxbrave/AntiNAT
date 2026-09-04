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
//
// repair-2 P1-A: the subscriber gate MUST be constructed via NewSSEHandler so
// subMu (the bounded semaphore) is initialized before any concurrent stream can
// touch it. Claiming a slot by writing subMu inside ServeHTTP was a data race
// on first concurrent hit (the old lazy-init wrote the channel while another
// request read it). ServeHTTP now only ever reads subMu. A zero-value handler
// (subMu == nil) fails closed: every stream is refused 503 UNAVAILABLE.
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
	// instead of buffering without limit (default 5s).
	WriteTimeout time.Duration

	subMu chan struct{}
}

// NewSSEHandler builds an SSEHandler with the bounded subscriber gate
// initialized. The configured values are normalized the same way ServeHTTP
// normalized them (poll interval >= 100ms, batch 1..200, at least one
// subscriber slot, write timeout >= 5s unless 0 means default), so the
// constructor result and the serve path agree on the gate capacity.
func NewSSEHandler(store EventStore, pollInterval time.Duration, batch, maxSubscribers int, writeTimeout time.Duration) *SSEHandler {
	if batch <= 0 || batch > 200 {
		batch = 100
	}
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	if maxSubscribers <= 0 {
		maxSubscribers = 64
	}
	if writeTimeout <= 0 {
		writeTimeout = 5 * time.Second
	}
	return &SSEHandler{
		Store:          store,
		PollInterval:   pollInterval,
		Batch:          batch,
		MaxSubscribers: maxSubscribers,
		WriteTimeout:   writeTimeout,
		subMu:          make(chan struct{}, maxSubscribers),
	}
}

func (h *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSSEError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
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
	writeTimeout := h.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 5 * time.Second
	}
	// Bounded subscriber gate (backpressure at the connection level). subMu is
	// only ever read here (P1-A); construction guarantees it is non-nil. A nil
	// subMu (zero-value handler) makes the send never ready, so the default
	// case fails closed with 503 rather than racing on a first-touch write.
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
	setWriteDeadline := func() bool {
		if writeTimeout <= 0 {
			return true
		}
		return controller.SetWriteDeadline(time.Now().Add(writeTimeout)) == nil
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
			if !setWriteDeadline() {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, sanitizeEventType(event.EventType), payload); err != nil {
				return
			}
			cursor = event.ID
		}
		if !setWriteDeadline() {
			return
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
	value = redactJSON(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func redactJSON(value any) any {
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
			v[key] = redactJSON(child)
		}
	case []any:
		for i, child := range v {
			v[i] = redactJSON(child)
		}
	case string:
		if credentialLikeValue(v) {
			return "[REDACTED]"
		}
	}
	return value
}

// secretFieldName reports whether a lowercased object key belongs to a secret
// family by name: token/secret/password/private_key substrings plus the exact
// authorization/api_key keys. This is the name-based security line and is kept
// conservative (it may over-redact, never under-redact).
func secretFieldName(lower string) bool {
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(lower)
	return strings.Contains(compact, "token") || strings.Contains(compact, "secret") ||
		strings.Contains(compact, "password") || strings.Contains(compact, "passwd") ||
		strings.Contains(compact, "privatekey") || strings.Contains(compact, "apikey") ||
		strings.Contains(compact, "credential") || strings.Contains(compact, "authorization") ||
		strings.Contains(compact, "cookie")
}

// credentialLikeValue reports whether a string under a generic key (for example
// the literal "value" key) is credential-shaped: a long opaque token, a hex or
// base64 secret, or a high-entropy mixed-class string. It deliberately excludes
// common legitimate event data — short labels, timestamps/dates/IPs/URLs, prose
// with spaces and structural identifiers — so redaction does not over-sweep a
// payload's real "value" (repair-2 P2-D).
func credentialLikeValue(v string) bool {
	if len(v) < 12 {
		return false
	}
	if structuredNonSecret(v) {
		return false
	}
	if !strings.ContainsAny(v, " 	\r\n") {
		return true
	}
	if len(v) >= 24 && !strings.ContainsAny(v, " 	") {
		return true
	}
	if hexTokenShape(v) || base64TokenShape(v) {
		return true
	}
	return highEntropyMixed(v)
}

func structuredNonSecret(v string) bool {
	if strings.Contains(v, "://") {
		// A URL is only structured/non-secret when it has no userinfo and no
		// credential-looking query or fragment. Never let URL syntax bypass
		// token/secret redaction.
		lower := strings.ToLower(v)
		if strings.Contains(lower, "@") || strings.ContainsAny(lower, "?#") {
			return false
		}
		return true // URL without credential-bearing userinfo/query
	}
	// Digit-dominated timestamp / datetime / IP / port / serial shapes.
	digits, letters := 0, 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letters++
		}
	}
	if letters <= 2 && digits*2 >= len(v) && strings.ContainsAny(v, "-:T") {
		return true
	}
	// UUID / MAC / hex-with-separators are public identifiers, not secrets.
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
	if hexCount >= 12 && sepCount >= 2 {
		return true
	}
	// Ambiguous opaque strings are safer to redact than to expose. The caller
	// already excludes short values; prose with whitespace remains structured.
	return strings.ContainsAny(v, " 	\r\n")
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

func writeSSEError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message, "request_id": "req"})
}
