package api

import (
	"net/http"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/auth"
)

// sessionCookieName is the frozen session cookie (api/openapi.yaml
// sessionAuth: in cookie, name antinat_session).
const sessionCookieName = "antinat_session"

// handleLogin implements POST /api/v1/auth/login.
func (a *apiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
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
	session, token, err := a.auth.Login(body.Username, body.Password)
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
func (a *apiServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, _ := r.Cookie(sessionCookieName)
	if token != nil {
		_ = a.auth.Logout(token.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// handleMe implements GET /api/v1/auth/me.
func (a *apiServer) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": user.ID, "username": user.Username})
}

// currentUser resolves the session cookie to a user.
func (a *apiServer) currentUser(r *http.Request) (auth.User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.User{}, false
	}
	user, err := a.auth.Me(cookie.Value)
	if err != nil {
		return auth.User{}, false
	}
	return user, true
}

// requireAuth wraps a handler with the session gate.
func (a *apiServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.currentUser(r); !ok {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "not authenticated")
			return
		}
		next(w, r)
	}
}
