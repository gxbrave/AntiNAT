package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RED P15 Story 1: unsafe cross-origin state-changing requests must be refused
// before the downstream handler runs.
func TestP15OriginMiddlewareRejectsCrossOriginMutation(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	h := SecurityMiddleware(next, SecurityConfig{AllowedOrigins: []string{"https://admin.example"}})
	req := httptest.NewRequest(http.MethodPost, "http://controller.test/api/v1/nodes", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.RemoteAddr = "192.0.2.1:1234"
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v, want forbidden without downstream", resp.Code, called)
	}

	called = false
	trusted := SecurityMiddleware(next, SecurityConfig{TrustedProxies: []string{"192.0.2.1"}})
	req = httptest.NewRequest(http.MethodPost, "http://controller.test/api/v1/nodes", nil)
	req.Header.Set("Origin", "https://public.example")
	req.Header.Set("X-Forwarded-Host", "public.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.RemoteAddr = "192.0.2.1:1234"
	resp = httptest.NewRecorder()
	trusted.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent || !called {
		t.Fatalf("trusted forwarded origin status=%d called=%v, want allowed", resp.Code, called)
	}
}
