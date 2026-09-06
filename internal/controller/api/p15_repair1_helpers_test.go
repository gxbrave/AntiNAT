package api_test

// Generic helpers shared by the P15 repair cycle-1 API tests. Router-composition
// helpers that depend on repair fields (SSE handler, CloseNodeSession) live in
// the per-item helper files so each repair commit stays self-contained.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func createNodeAPI(t *testing.T, srv *httptest.Server, cookie *http.Cookie) (id, etag string) {
	t.Helper()
	resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/nodes", cookie, map[string]any{"name": "node-api"}, "node-repair-create-1")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create node = %d (%s)", resp.StatusCode, body)
	}
	var node map[string]any
	_ = json.Unmarshal(body, &node)
	return node["id"].(string), node["etag"].(string)
}

func createForwardAPI(t *testing.T, srv *httptest.Server, cookie *http.Cookie, nodeID string) string {
	t.Helper()
	resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/forwards", cookie,
		map[string]any{"node_id": nodeID, "name": "web", "protocol": "tcp", "target": "10.0.0.5:8080", "strategy": "direct-v4"},
		"fwd-repair-key-0001")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create forward = %d (%s)", resp.StatusCode, body)
	}
	var fwd map[string]any
	_ = json.Unmarshal(body, &fwd)
	id := fwd["id"].(string)
	if id == "" {
		t.Fatalf("forward id missing: %s", body)
	}
	return id
}

func doReqIfMatch(t *testing.T, srv *httptest.Server, method, path string, cookie *http.Cookie, body any, etag string) (*http.Response, []byte) {
	t.Helper()
	return doReqKey(t, srv, method, path, cookie, body, "", etag)
}

func doReqKey(t *testing.T, srv *httptest.Server, method, path string, cookie *http.Cookie, body any, key string, etag ...string) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if len(etag) > 0 && etag[0] != "" {
		req.Header.Set("If-Match", etag[0])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}
