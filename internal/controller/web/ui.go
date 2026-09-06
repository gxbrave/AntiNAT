// UI route registration (P17 Story 2). Composed into the minimal admin router
// in router_min.go: the public home at /, the admin shell at /admin, and the
// embedded /static subtree. All dynamic pages are server-rendered Go templates
// with bilingual system strings; no second styling framework.
package web

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// sessionCookieName is the frozen session cookie name (api/openapi.yaml
// sessionAuth: in cookie, name antinat_session). Kept in sync with the api
// package constant.
const sessionCookieName = "antinat_session"

// uiHandlers is the shared page-render state for the public home and admin
// shell. It reads the controller store directly (server-side rendering) and
// the auth service only to decide the private-site session gate.
type uiHandlers struct {
	store  *store.Store
	auth   *auth.AuthService
	i18n   *I18N
	tmpl   *template.Template
	static http.Handler
}

// registerUI mounts the public home, admin shell, and static asset routes onto
// mux. It must run after api routes are registered so the root only serves
// paths the API does not own.
func registerUI(mux *http.ServeMux, cfg api.RouterConfig) error {
	if cfg.Store == nil {
		return errors.New("web: ui store is required")
	}
	if cfg.Auth == nil {
		return errors.New("web: ui auth service is required")
	}
	tmpl, i18n, err := parseTemplates()
	if err != nil {
		return err
	}
	stat, err := staticFileServer()
	if err != nil {
		return err
	}
	h := &uiHandlers{store: cfg.Store, auth: cfg.Auth, i18n: i18n, tmpl: tmpl, static: stat}
	mux.Handle("/static/", http.StripPrefix("/static/", stat))
	mux.HandleFunc("/{$}", h.handleHome)
	mux.HandleFunc("/admin", h.handleAdmin)
	return nil
}

// currentUser resolves the session cookie to a user, mirroring the API package.
func (h *uiHandlers) currentUser(r *http.Request) (auth.User, bool) {
	if h == nil || h.auth == nil {
		return auth.User{}, false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.User{}, false
	}
	user, err := h.auth.Me(cookie.Value)
	if err != nil {
		return auth.User{}, false
	}
	return user, true
}
