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
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/hook"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// RouterConfig wires the minimal API.
type RouterConfig struct {
	Store          *store.Store
	Auth           *auth.AuthService
	SSE            http.Handler
	AllowedOrigins []string
	TrustedProxies []string
	MaxBodyBytes   int64
	// CloseNodeSession terminates an ESTABLISHED control session for a node.
	// The App composes it with the agent hub's ForceCloseNodeSession so a force
	// node delete cannot leave an online session delivering stale commands
	// (repair-1 H3).
	CloseNodeSession func(nodeID string)
	// Hooks is the P16 hook service (hook definitions, encrypted secrets,
	// delivery retry). When nil, the /api/v1/hooks/* and hook-deliveries routes
	// are not registered (minimal setups without the hook pool).
	Hooks *hook.Service
}

// ErrorBody is the frozen error envelope (docs/error-codes.md §1).
type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id"`
	Details   map[string]any `json:"details,omitempty"`
}

// writeError writes the frozen error envelope. Middleware supplies a request
// id; the fallback keeps direct handler tests deterministic.
func writeError(w http.ResponseWriter, status int, code, message string) {
	requestID := w.Header().Get("X-Request-ID")
	if requestID == "" {
		requestID = "req"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorBody{Code: code, Message: message, RequestID: requestID})
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON decodes a strict JSON object body into v.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r == nil || r.Body == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body")
		return false
	}
	// Keep an API-local cap even when a handler is mounted without the web
	// middleware. MaxBytesReader returns *http.MaxBytesError; classify that
	// sentinel explicitly rather than guessing from the number of bytes read.
	limited := http.MaxBytesReader(w, r.Body, protocol.MaxPayloadBytes)
	raw, err := io.ReadAll(limited)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body exceeds the payload limit")
		} else {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body")
		}
		return false
	}
	if err := protocol.DecodeStrictJSONInto(raw, v); err != nil {
		if errors.Is(err, protocol.ErrPayloadTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body exceeds the payload limit")
		} else {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body")
		}
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
	store        *store.Store
	auth         *auth.AuthService
	health       *healthState
	sse          http.Handler
	login        *loginLimiter
	closeSession func(nodeID string)
	hooks        *hook.Service
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
	s := &Server{store: cfg.Store, auth: cfg.Auth, health: newHealthState(), sse: cfg.SSE, login: newLoginLimiter(), closeSession: cfg.CloseNodeSession, hooks: cfg.Hooks}
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
	mux.HandleFunc("/api/v1/nodes/", s.requireAuth(s.handleNodeRoutes))
	mux.HandleFunc("/api/v1/node-deletions/", s.requireAuth(s.handleNodeDeletionPath))

	mux.HandleFunc("/api/v1/forwards", s.requireAuth(s.handleForwards))
	mux.HandleFunc("/api/v1/forwards/", s.requireAuth(s.handleForwardRoutes))
	mux.HandleFunc("/api/v1/forward-deletions/", s.requireAuth(s.handleDeletionPollPath))
	mux.HandleFunc("/api/v1/navigation/", s.requireAuth(s.handleNavigation))
	if s.sse != nil {
		// canonical durable bounded SSE handler composed by the App (repair-1 H8).
		mux.HandleFunc("/api/v1/events", s.requireAuth(s.sse.ServeHTTP))
	} else {
		// Fallback local poller keeps the route reachable in minimal setups.
		mux.HandleFunc("/api/v1/events", s.requireAuth(s.handleEvents))
	}
	mux.HandleFunc("/api/v1/traffic", s.requireAuth(s.handleTraffic))
	mux.HandleFunc("/api/v1/audit", s.requireAuth(s.handleAudit))
	mux.HandleFunc("/api/v1/settings", s.requireAuth(s.handleSettings))
	if s.hooks != nil {
		// Frozen hook surface (P16): definitions, encrypted secret metadata
		// (values never returned), and delivery retry. Registered only when a
		// hook service is composed.
		mux.HandleFunc("/api/v1/hooks/definitions", s.requireAuth(s.handleHookDefinitions))
		mux.HandleFunc("/api/v1/hooks/definitions/", s.requireAuth(s.handleHookDefinitionByID))
		mux.HandleFunc("/api/v1/hooks/secrets", s.requireAuth(s.handleHookSecrets))
		mux.HandleFunc("/api/v1/hooks/secrets/", s.requireAuth(s.handleHookSecretByID))
		mux.HandleFunc("/api/v1/hook-deliveries/", s.requireAuth(s.handleHookDeliveryRoute))
	}
}

// handleInit implements POST /api/v1/auth/init (P10 bootstrap surface, not in
// the frozen openapi: the frozen API has no bootstrap endpoint, and the M1
// CLI needs a one-time admin creation path). Only an empty store may be
// initialized without a session. Once an administrator exists, callers must
// authenticate before receiving the safe conflict response.
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
	count, err := s.store.CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "admin init failed")
		return
	}
	if count != 0 {
		if _, ok := s.currentUser(r); !ok {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "administrator initialization requires authentication")
			return
		}
		writeError(w, http.StatusConflict, "CONFLICT", "an administrator already exists")
		return
	}
	if err := s.auth.BootstrapAdmin(body.Username, body.Password); err != nil {
		if errors.Is(err, auth.ErrAdminAlreadyInitialized) {
			if _, ok := s.currentUser(r); !ok {
				writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "administrator initialization requires authentication")
				return
			}
			writeError(w, http.StatusConflict, "CONFLICT", "an administrator already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "admin init failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"username": body.Username, "created": true})
}

// handleLogin implements POST /api/v1/auth/login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	key := loginRateKey(r)
	if !s.login.allow(key) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "login rate limit exceeded")
		return
	}
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
		SameSite: http.SameSiteStrictMode,
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
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
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
func loginRateKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

type loginRateEntry struct {
	windowStart time.Time
	count       int
}

// maxLoginLimiterPeers bounds the per-peer login attempt map so a synthetic
// flood of distinct source IPs cannot grow controller memory without bound
// (repair-1 M3). When the map is saturated, expired windows are evicted first;
// a brand-new peer is then refused fail-closed until capacity frees.
const maxLoginLimiterPeers = 4096

type loginLimiter struct {
	mu         sync.Mutex
	now        func() time.Time
	limit      int
	window     time.Duration
	maxEntries int
	entries    map[string]loginRateEntry
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{now: time.Now, limit: 10, window: time.Minute, maxEntries: maxLoginLimiterPeers, entries: make(map[string]loginRateEntry)}
}

func (l *loginLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, exists := l.entries[key]; !exists && len(l.entries) >= l.maxEntries {
		l.evictExpiredLocked(now)
		if len(l.entries) >= l.maxEntries {
			// Saturated with in-window peers: refuse the new peer rather than
			// growing the map.
			return false
		}
	}
	entry := l.entries[key]
	if entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= l.window {
		entry = loginRateEntry{windowStart: now}
	}
	if entry.count >= l.limit {
		l.entries[key] = entry
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

func (l *loginLimiter) evictExpiredLocked(now time.Time) {
	for k, e := range l.entries {
		if !e.windowStart.IsZero() && now.Sub(e.windowStart) >= l.window {
			delete(l.entries, k)
		}
	}
}

func (l *loginLimiter) peerCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

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
