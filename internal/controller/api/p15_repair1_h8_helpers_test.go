package api_test

// Router-composition helper for the H8 SSE tests: builds the router with the
// canonical durable bounded SSE handler mounted, mirroring App composition.

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
)

func newTestServerWithSSE(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.NewService(st)
	handler, err := web.NewRouter(api.RouterConfig{Store: st, Auth: svc, ControllerPublicKey: testRouterControllerPublicKey(t), SSE: web.NewSSEHandler(st, 0, 0, 0, 0)})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, st
}
