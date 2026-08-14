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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

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

// sessionCookieName is the frozen session cookie (api/openapi.yaml
// sessionAuth: in cookie, name antinat_session).
const sessionCookieName = "antinat_session"

// Server is the minimal API server (Story 4): it owns the handler state and
// registers its routes onto a caller-provided mux (the minimal router in
// internal/controller/web builds that mux).
type Server struct {
	store  *store.Store
	auth   *auth.AuthService
	health *healthState
	// idempotencyMu closes the create-side effect window within one API
	// process; the durable store still owns replay/conflict decisions.
	idempotencyMu sync.Mutex
}

// NewServer validates config and builds the minimal API server.
func NewServer(cfg RouterConfig) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: store is required")
	}
	if cfg.Auth == nil {
		return nil, errors.New("api: auth service is required")
	}
	s := &Server{store: cfg.Store, auth: cfg.Auth, health: newHealthState()}
	s.health.setStoreReady(true)
	s.health.setAuthReady(true)
	return s, nil
}

// RegisterRoutes mounts every minimal-API route on mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.health.handleHealthz)
	mux.HandleFunc("/readyz", s.health.handleReadyz)

	mux.HandleFunc("/api/v1/auth/init", s.handleInit)
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/v1/auth/me", s.requireAuth(s.handleMe))

	mux.HandleFunc("/api/v1/nodes", s.requireAuth(s.handleNodes))
	mux.HandleFunc("/api/v1/nodes/", s.requireAuth(s.handleNodeByID))

	mux.HandleFunc("/api/v1/forwards", s.requireAuth(s.handleForwards))
	mux.HandleFunc("/api/v1/forwards/", s.requireAuth(s.handleForwardByID))
	mux.HandleFunc("/api/v1/forward-deletions/", s.requireAuth(s.handleDeletionPollPath))
}

// handleInit implements POST /api/v1/auth/init (P10 bootstrap surface, not in
// the frozen openapi: the frozen API has no bootstrap endpoint, and the M1
// CLI needs a one-time admin creation path). It refuses when an admin
// already exists.
func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Username == "" || len(body.Password) < 8 {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "username and a password of at least 8 chars are required")
		return
	}
	password, created, err := s.auth.EnsureAdmin(body.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "admin init failed")
		return
	}
	if !created {
		writeError(w, http.StatusConflict, "CONFLICT", "an administrator already exists")
		return
	}
	_ = password
	// Rotate to the operator-provided password.
	enc, err := auth.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "password hashing failed")
		return
	}
	user, err := s.store.GetUserByUsername(body.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "admin lookup failed")
		return
	}
	if err := s.store.SetUserPassword(user.ID, enc.Algorithm, enc.Hash); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "password rotation failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"username": body.Username, "created": true})
}

// handleLogin implements POST /api/v1/auth/login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "username and password are required")
		return
	}
	session, token, err := s.auth.Login(body.Username, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid credentials")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(session.ExpiresAt, 0),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       map[string]string{"id": session.User.ID, "username": session.User.Username},
		"session_id": session.ID,
	})
}

// handleLogout implements POST /api/v1/auth/logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, _ := r.Cookie(sessionCookieName)
	if token != nil {
		_ = s.auth.Logout(token.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// handleMe implements GET /api/v1/auth/me.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": user.ID, "username": user.Username})
}

// currentUser resolves the session cookie to a user.
func (s *Server) currentUser(r *http.Request) (auth.User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.User{}, false
	}
	user, err := s.auth.Me(cookie.Value)
	if err != nil {
		return auth.User{}, false
	}
	return user, true
}

// requireAuth wraps a handler with the session gate.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.currentUser(r); !ok {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "not authenticated")
			return
		}
		next(w, r)
	}
}

// --- shared helpers ---

// etagFor renders the frozen ETag for a revision.
func etagFor(revision uint64) string {
	return fmt.Sprintf("\"rev-%d\"", revision)
}

// splitPath splits a path remainder on '/'.
func splitPath(rest string) []string {
	var out []string
	cur := ""
	for _, c := range rest {
		if c == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// randomHexID returns a 128-bit random hex identifier.
func randomHexID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomNodeID returns a node id that fits the frozen control wire format
// (node_id is raw 1..16 bytes, protocol.md §3): 8 random bytes hex-encoded
// is exactly 16 ASCII bytes. The previous 32-hex-char id was rejected by
// enrollment (found by the M1 walking skeleton).
func randomNodeID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requestHashOf hashes the canonical JSON of the decoded request body.
func requestHashOf(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
