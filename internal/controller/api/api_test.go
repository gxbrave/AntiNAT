package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
)

// newTestServer builds a controller store + minimal API server.
func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.NewService(st)
	handler, err := web.NewRouter(api.RouterConfig{Store: st, Auth: svc})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, st
}

// mustETag fetches a forward and returns its current etag.
func mustETag(t *testing.T, srv *httptest.Server, cookie *http.Cookie, fwdID string) string {
	t.Helper()
	resp, body := doReq(t, srv, http.MethodGet, "/api/v1/forwards/"+fwdID, cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get forward %s = %d (%s)", fwdID, resp.StatusCode, body)
	}
	var fwd map[string]any
	_ = json.Unmarshal(body, &fwd)
	etag, _ := fwd["etag"].(string)
	if etag == "" {
		t.Fatalf("etag missing: %s", body)
	}
	return etag
}

// initAdmin creates the first admin and returns its credentials.
func initAdmin(t *testing.T, srv *httptest.Server, st *store.Store) (username, password string) {
	t.Helper()
	password = "s3cret-pass-123"
	enc, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(store.UserRecord{ID: "u1", Username: "admin", PasswordHash: enc.Hash, PasswordAlgorithm: enc.Algorithm}); err != nil {
		t.Fatal(err)
	}
	return "admin", password
}

// login returns the session cookie for the admin.
func login(t *testing.T, srv *httptest.Server, username, password string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	for _, c := range cookies {
		if c.Name == "antinat_session" {
			return c
		}
	}
	t.Fatal("no session cookie in login response")
	return nil
}

func doReq(t *testing.T, srv *httptest.Server, method, path string, cookie *http.Cookie, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

// TestUnauthenticatedAccessFails covers Story 4 RED: every management route
// refuses unauthenticated access with 401.
func TestUnauthenticatedAccessFails(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{
		"/api/v1/auth/me",
		"/api/v1/nodes",
		"/api/v1/forwards",
	} {
		resp, body := doReq(t, srv, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401 (body %s)", path, resp.StatusCode, body)
		}
		var e api.ErrorBody
		if err := json.Unmarshal(body, &e); err != nil || e.Code != "UNAUTHENTICATED" {
			t.Fatalf("%s: error body = %s", path, body)
		}
	}
}

// TestLoginLogoutMe covers the auth surface: login sets a session cookie,
// /me resolves it, logout revokes it.
func TestLoginLogoutMe(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)

	cookie := login(t, srv, user, pass)

	resp, body := doReq(t, srv, http.MethodGet, "/api/v1/auth/me", cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d (%s)", resp.StatusCode, body)
	}
	var me map[string]string
	_ = json.Unmarshal(body, &me)
	if me["username"] != "admin" {
		t.Fatalf("me = %s", body)
	}

	resp, _ = doReq(t, srv, http.MethodPost, "/api/v1/auth/logout", cookie, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	resp, _ = doReq(t, srv, http.MethodGet, "/api/v1/auth/me", cookie, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d, want 401", resp.StatusCode)
	}
}

// TestNodeCreateAndToken covers the node surface: create with an
// Idempotency-Key, issue a single-use enrollment token (shown once).
func TestNodeCreateAndToken(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	// Create a node.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/nodes", bytes.NewReader([]byte(`{"name":"node-a"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "node-create-0001")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create node status = %d (%s)", resp.StatusCode, body)
	}
	var node map[string]any
	_ = json.Unmarshal(body, &node)
	nodeID, _ := node["id"].(string)
	if nodeID == "" {
		t.Fatalf("node id missing: %s", body)
	}
	if etag, _ := node["etag"].(string); etag == "" {
		t.Fatalf("node etag missing: %s", body)
	}

	// Enrollment token (shown once).
	resp, body = doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/enrollment-token", cookie, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("token status = %d (%s)", resp.StatusCode, body)
	}
	var tok map[string]any
	_ = json.Unmarshal(body, &tok)
	plain, _ := tok["token"].(string)
	if len(plain) < 20 {
		t.Fatalf("token not shown: %s", body)
	}
	// The token row must be hash-only.
	count, err := st.CountEnrollmentTokens()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("token rows = %d, want 1", count)
	}
}

// TestForwardCreateListDelete covers the minimal forward surface: create,
// list, patch with If-Match, and delete with If-Match.
func TestForwardCreateListDelete(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	// Create a node.
	req0, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/nodes", bytes.NewReader([]byte(`{"name":"node-a"}`)))
	req0.Header.Set("Content-Type", "application/json")
	req0.Header.Set("Idempotency-Key", "node-create-0002")
	req0.AddCookie(cookie)
	resp0, err0 := http.DefaultClient.Do(req0)
	if err0 != nil {
		t.Fatal(err0)
	}
	body0, _ := io.ReadAll(resp0.Body)
	resp0.Body.Close()
	if resp0.StatusCode != http.StatusCreated {
		t.Fatalf("create node: %d (%s)", resp0.StatusCode, body0)
	}
	var node map[string]any
	_ = json.Unmarshal(body0, &node)
	nodeID := node["id"].(string)

	// Missing If-Match on PATCH => 428.
	resp, _ := doReq(t, srv, http.MethodPatch, "/api/v1/forwards/nonexistent", cookie, map[string]any{"target": "10.0.0.1:80"})
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("patch without If-Match = %d, want 428", resp.StatusCode)
	}

	// Create a forward (Idempotency-Key).
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/forwards", bytes.NewReader([]byte(
		`{"node_id":"`+nodeID+`","name":"web","protocol":"tcp","target":"10.0.0.5:8080","strategy":"direct-v4"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "key-12345678")
	req.AddCookie(cookie)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("create forward = %d (%s)", resp2.StatusCode, body2)
	}
	var fwd map[string]any
	_ = json.Unmarshal(body2, &fwd)
	fwdID := fwd["id"].(string)
	etag := fwd["etag"].(string)
	if fwdID == "" || etag == "" {
		t.Fatalf("forward fields missing: %s", body2)
	}

	// List forwards.
	resp, body := doReq(t, srv, http.MethodGet, "/api/v1/forwards", cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list forwards = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), fwdID) {
		t.Fatalf("forward not listed: %s", body)
	}

	// PATCH with If-Match succeeds (target hot update).
	patchReq, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/forwards/"+fwdID,
		bytes.NewReader([]byte(`{"target":"10.0.0.6:8081"}`)))
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("If-Match", etag)
	patchReq.AddCookie(cookie)
	resp3, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatal(err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("patch forward = %d (%s)", resp3.StatusCode, body3)
	}

	// PATCH with a stale If-Match => 412.
	staleReq, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/forwards/"+fwdID,
		bytes.NewReader([]byte(`{"target":"10.0.0.7:8082"}`)))
	staleReq.Header.Set("Content-Type", "application/json")
	staleReq.Header.Set("If-Match", etag)
	staleReq.AddCookie(cookie)
	resp4, err := http.DefaultClient.Do(staleReq)
	if err != nil {
		t.Fatal(err)
	}
	body4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale patch = %d, want 412 (%s)", resp4.StatusCode, body4)
	}

	// DELETE with If-Match => 202 with an operation id.
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/forwards/"+fwdID, nil)
	delReq.Header.Set("If-Match", mustETag(t, srv, cookie, fwdID))
	delReq.AddCookie(cookie)
	resp5, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	body5, _ := io.ReadAll(resp5.Body)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusAccepted {
		t.Fatalf("delete forward = %d (%s)", resp5.StatusCode, body5)
	}
	var op map[string]any
	_ = json.Unmarshal(body5, &op)
	if op["operation_id"] == nil {
		t.Fatalf("delete response missing operation_id: %s", body5)
	}
}

// TestIdempotencyConflict covers Story 4 RED: the same Idempotency-Key with a
// different request body is a 409.
func TestIdempotencyConflict(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	post := func(body string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/nodes", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "key-abcdefgh")
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if got := post(`{"name":"a"}`); got != http.StatusCreated {
		t.Fatalf("first post = %d", got)
	}
	if got := post(`{"name":"b"}`); got != http.StatusConflict {
		t.Fatalf("conflicting post = %d, want 409", got)
	}
}
