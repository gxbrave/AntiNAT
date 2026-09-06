package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
)

// RED P15 Story 1: an oversized but otherwise valid request is a distinct
// payload error, and every response receives a unique request id.
func TestP15OversizedBodyIs413WithUniqueRequestIDs(t *testing.T) {
	srv, _ := newTestServer(t)
	body := []byte(`{"username":"` + strings.Repeat("u", 65520) + `","password":"operator-password"}`)
	ids := make([]string, 2)
	for i := range ids {
		resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized login status=%d body=%s, want 413", resp.StatusCode, payload)
		}
		var envelope api.ErrorBody
		if err := json.Unmarshal(payload, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Code != "PAYLOAD_TOO_LARGE" || envelope.RequestID == "" {
			t.Fatalf("error envelope=%+v", envelope)
		}
		ids[i] = envelope.RequestID
	}
	if ids[0] == ids[1] {
		t.Fatalf("request ids reused: %q", ids[0])
	}
}

// RED P15 Story 2: the frozen node PATCH route requires If-Match and exposes a
// revision-bumped ETag after a successful update.
func TestP15NodePatchRequiresAndAdvancesETag(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	req0, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/nodes", strings.NewReader(`{"name":"patch-node"}`))
	req0.Header.Set("Content-Type", "application/json")
	req0.Header.Set("Idempotency-Key", "patch-node-key")
	req0.AddCookie(cookie)
	resp, err := srv.Client().Do(req0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create node=%d body=%s", resp.StatusCode, body)
	}
	var node map[string]any
	if err := json.Unmarshal(body, &node); err != nil {
		t.Fatal(err)
	}
	nodeID, _ := node["id"].(string)
	etag, _ := node["etag"].(string)
	if nodeID == "" || etag == "" {
		t.Fatalf("node=%s", body)
	}
	resp, body = doReq(t, srv, http.MethodPatch, "/api/v1/nodes/"+nodeID, cookie, map[string]any{"name": "renamed"})
	if resp.StatusCode != http.StatusPreconditionRequired && resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("missing If-Match=%d body=%s", resp.StatusCode, body)
	}
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/nodes/"+nodeID, strings.NewReader(`{"name":"renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", etag)
	req.AddCookie(cookie)
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node patch=%d body=%s", resp.StatusCode, body)
	}
	var updated map[string]any
	_ = json.Unmarshal(body, &updated)
	if updated["etag"] == etag || updated["name"] != "renamed" {
		t.Fatalf("updated node=%s", body)
	}
}

// RED P15 Story 3: settings and navigation are authenticated, durable routes;
// secrets must not be reflected in settings responses.
func TestP15SettingsAndNavigationRoutes(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	resp, body := doReq(t, srv, http.MethodGet, "/api/v1/settings", cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings get=%d body=%s", resp.StatusCode, body)
	}
	resp, body = doReq(t, srv, http.MethodPost, "/api/v1/navigation/categories", cookie, map[string]any{"name": "home"})
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusCreated {
		t.Fatalf("category create=%d body=%s", resp.StatusCode, body)
	}
	_ = st
}

// RED P15 Story 4: events replay from Last-Event-ID and redact secret-shaped
// fields before they reach an SSE client.
func TestP15EventsResumeAndRedactsSecrets(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	if _, err := st.AppendAdminEvent("test", `{"safe":"yes","token":"do-not-send"}`); err != nil {
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
	if !strings.Contains(text, "id:") || strings.Contains(text, "do-not-send") {
		t.Fatalf("events payload=%q", text)
	}
}
