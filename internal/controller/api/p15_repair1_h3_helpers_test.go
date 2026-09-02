package api_test

// Router-composition helper for the H3 node-deletion tests: builds the router
// with a recording command-session closer.

import (
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
)

var closerCalls atomic.Int32

func newTestServerWithCloser(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	closerCalls.Store(0)
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.NewService(st)
	handler, err := web.NewRouter(api.RouterConfig{
		Store: st, Auth: svc,
		CloseNodeSession: func(nodeID string) { closerCalls.Add(1) },
	})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, st
}
