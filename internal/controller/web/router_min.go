// Minimal admin router (P10 Story 4).
//
// The minimal authenticated admin API surface used by the M1 walking
// skeleton: healthz/readyz, auth login/logout/me, nodes, forwards and
// forward-deletion polling. Handlers live in internal/controller/api; this
// package owns the router (mux assembly and wiring) so P15 can extend or
// replace it serially without touching the handler package.
package web

import (
	"errors"
	"net/http"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
)

// NewRouter builds the minimal admin API router.
func NewRouter(cfg api.RouterConfig) (http.Handler, error) {
	if cfg.Store == nil {
		return nil, errors.New("web: store is required")
	}
	if cfg.Auth == nil {
		return nil, errors.New("web: auth service is required")
	}
	s, err := api.NewServer(cfg)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	return SecurityMiddleware(mux, SecurityConfig{
		AllowedOrigins: cfg.AllowedOrigins,
		TrustedProxies: cfg.TrustedProxies,
		MaxBodyBytes:   cfg.MaxBodyBytes,
	}), nil
}
