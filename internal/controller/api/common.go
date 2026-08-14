// Minimal authenticated admin API (P10 Story 4).
//
// Implements the frozen openapi surface needed by the M1 walking skeleton:
// healthz/readyz, auth login/logout/me, nodes list/create/enrollment-token,
// forwards list/create/patch/delete and deletion polling. Every mutation uses
// ETag/If-Match (428 missing, 412 stale) and creates carry Idempotency-Key
// (409 on conflict); secrets (passwords, enrollment tokens) are shown exactly
// once and never stored in plaintext (docs/error-codes.md §4/§5).
package api

import (
	"encoding/json"
	"net/http"

	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RouterConfig wires the minimal API.
type RouterConfig struct {
	Store *store.Store
	Auth  *auth.AuthService
}

// ErrorBody is the frozen error envelope (docs/error-codes.md §1).
type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id"`
	Details   map[string]any `json:"details,omitempty"`
}

// writeError writes the frozen error envelope.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorBody{Code: code, Message: message, RequestID: "req"})
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON decodes a strict JSON object body into v.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body")
		return false
	}
	return true
}
