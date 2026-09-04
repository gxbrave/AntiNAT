package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestDeploymentProfileRoundTripUsesETagAndStoresNoSecret(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	nodeID, _ := createNodeAPI(t, srv, cookie)
	events, err := st.AdminEventsAfter(0, 20)
	if err != nil {
		t.Fatalf("AdminEventsAfter: %v", err)
	}
	foundNodeCreated := false
	for _, event := range events {
		if event.EventType == "NODE_CREATED" && strings.Contains(event.Payload, nodeID) {
			foundNodeCreated = true
			break
		}
	}
	if !foundNodeCreated {
		t.Fatalf("node create did not append NODE_CREATED event: %+v", events)
	}
	path := "/api/v1/nodes/" + nodeID + "/deployment-profile"

	resp, body := doReq(t, srv, http.MethodGet, path, cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial deployment profile GET = %d (%s)", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want private, no-store", got)
	}
	var initial struct {
		NodeID  string         `json:"node_id"`
		ETag    string         `json:"etag"`
		Profile map[string]any `json:"profile"`
	}
	if err := json.Unmarshal(body, &initial); err != nil {
		t.Fatalf("decode initial profile: %v", err)
	}
	if initial.NodeID != nodeID || initial.ETag != `"rev-0"` {
		t.Fatalf("initial profile envelope = %s", body)
	}
	if _, ok := initial.Profile["token"]; ok {
		t.Fatal("initial profile exposes token")
	}

	profile := map[string]any{
		"platform":            "linux",
		"controller_endpoint": "https://ctl.example.test:3111/base/",
		"bind_interface":      "eth0; echo still-one-argument",
		"detection_scheduler": "parallel",
		"github_proxy":        "ghfast.top/",
		"install_dir":         "/opt/anti nat",
		"service_name":        "antinat-agent.service",
		"log_level":           "info",
		"auto_update":         "disabled",
		"token":               "must-not-be-accepted-or-stored",
		"command":             "must-not-be-accepted-or-stored",
	}
	resp, body = doReqIfMatch(t, srv, http.MethodPut, path, cookie, map[string]any{"profile": profile}, initial.ETag)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("profile containing secret fields = %d (%s), want 400", resp.StatusCode, body)
	}

	delete(profile, "token")
	delete(profile, "command")
	resp, body = doReqIfMatch(t, srv, http.MethodPut, path, cookie, map[string]any{"profile": profile}, initial.ETag)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile PUT = %d (%s)", resp.StatusCode, body)
	}
	var saved struct {
		Revision uint64         `json:"revision"`
		ETag     string         `json:"etag"`
		Profile  map[string]any `json:"profile"`
	}
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatalf("decode saved profile: %v", err)
	}
	if saved.Revision != 1 || saved.ETag != `"rev-1"` {
		t.Fatalf("saved revision/etag = %d/%q, want 1/ rev-1", saved.Revision, saved.ETag)
	}
	if got := saved.Profile["controller_endpoint"]; got != "https://ctl.example.test:3111/base" {
		t.Fatalf("normalized endpoint = %v", got)
	}
	if raw := stProfileJSON(t, st, nodeID); strings.Contains(raw, "must-not-be-accepted") || strings.Contains(raw, "command") || strings.Contains(raw, "token") {
		t.Fatalf("stored profile contains forbidden material: %s", raw)
	}

	resp, body = doReqIfMatch(t, srv, http.MethodPut, path, cookie, map[string]any{"profile": profile}, initial.ETag)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale deployment profile PUT = %d (%s), want 412", resp.StatusCode, body)
	}

	resp, body = doReq(t, srv, http.MethodGet, path, cookie, nil)
	var fetched struct {
		ETag string `json:"etag"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &fetched) != nil || fetched.ETag != `"rev-1"` {
		t.Fatalf("saved deployment profile GET = %d (%s)", resp.StatusCode, body)
	}
}

func TestDeploymentProfileRequiresAuthAndRejectsInvalidProfile(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	nodeID, _ := createNodeAPI(t, srv, cookie)
	path := "/api/v1/nodes/" + nodeID + "/deployment-profile"

	resp, body := doReq(t, srv, http.MethodGet, path, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated profile GET = %d (%s), want 401", resp.StatusCode, body)
	}

	resp, body = doReq(t, srv, http.MethodPost, path, cookie, map[string]any{"profile": map[string]any{}})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST deployment profile = %d (%s), want 405", resp.StatusCode, body)
	}
	resp, body = doReq(t, srv, http.MethodPut, path, cookie, map[string]any{"profile": map[string]any{}})
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("PUT without If-Match = %d (%s), want 428", resp.StatusCode, body)
	}

	resp, body = doReqIfMatch(t, srv, http.MethodPut, path, cookie, map[string]any{
		"profile": map[string]any{
			"platform":            "solaris",
			"controller_endpoint": "javascript:alert(1)",
		},
	}, `"rev-0"`)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid deployment profile = %d (%s), want 422", resp.StatusCode, body)
	}
	resp, body = doReqIfMatch(t, srv, http.MethodPut, path, cookie, map[string]any{
		"profile": map[string]any{
			"platform":            "linux",
			"controller_endpoint": "https://ctl.example.test",
		},
	}, `"rev-0"`)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("profile missing required fields = %d (%s), want 422", resp.StatusCode, body)
	}
	deletePath := "/api/v1/nodes/" + nodeID + "/delete"
	resp, body = doReqIfMatch(t, srv, http.MethodPost, deletePath, cookie, map[string]any{"mode": "normal"}, `"rev-999"`)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale node delete = %d (%s), want 412", resp.StatusCode, body)
	}
}

func stProfileJSON(t *testing.T, st *store.Store, nodeID string) string {
	t.Helper()
	rec, err := st.GetDeploymentProfile(nodeID)
	if err != nil {
		t.Fatalf("GetDeploymentProfile: %v", err)
	}
	return rec.JSON
}
