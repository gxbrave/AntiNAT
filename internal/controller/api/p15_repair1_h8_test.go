package api_test

// P15 repair cycle-1 RED H8 API test: before the App composed the canonical
// bounded SSE handler through RouterConfig.SSE, the durable bounded stream was
// never mounted and the frozen /api/v1/events route fell back to (or, in the
// reviewer's reading, was entirely) unreachable. The composed handler must be
// reachable and must replay + redact.

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestP15Repair1H8EventsRouteReachableWithComposedSSE(t *testing.T) {
	srv, st := newTestServerWithSSE(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	if _, err := st.AppendAdminEvent("test", `{"safe":"yes","password":"nope"}`); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events", nil)
	req.AddCookie(cookie)
	req.Header.Set("Last-Event-ID", "0")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("events status=%d content-type=%q body=%s", resp.StatusCode, resp.Header.Get("Content-Type"), payload)
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	text := string(buf[:n])
	if !strings.Contains(text, "id:") || strings.Contains(text, "nope") {
		t.Fatalf("events payload=%q", text)
	}
}
