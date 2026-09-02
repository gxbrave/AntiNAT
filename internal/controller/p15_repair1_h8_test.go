package controller

// P15 repair cycle-1 RED H8 App test: the composed App router responds to the
// frozen /api/v1/events route (404 before the canonical SSE handler was
// mounted through RouterConfig.SSE).

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestP15Repair1AppEventsRouteReachable(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown(t.Context())
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + app.Addr() + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("events route is 404; the composed SSE handler must be mounted")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("events without auth = %d, want 401 (route reachable behind auth)", resp.StatusCode)
	}
}
