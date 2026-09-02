package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
	"github.com/gxbrave/AntiNAT/internal/hook"
)

// newHooksTestServer builds a controller store + API server with the hook
// service composed (routes registered), returning the server, store, and hook
// service.
func newHooksTestServer(t *testing.T) (*httptest.Server, *store.Store, *hook.Service) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc, err := hook.NewService(hook.ServiceConfig{
		DBPath:  dbPath,
		KeyPath: filepath.Join(t.TempDir(), "hook-secret.key"),
		Sender:  nil,
	})
	if err != nil {
		t.Fatalf("hook service: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	handler, err := web.NewRouter(api.RouterConfig{Store: st, Auth: auth.NewService(st), Hooks: svc})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, st, svc
}

func doReqKey2(t *testing.T, srv *httptest.Server, method, path string, cookie *http.Cookie, body any, key string) (*http.Response, []byte) {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func createHookDef(t *testing.T, srv *httptest.Server, cookie *http.Cookie, name, url string) (string, string) {
	t.Helper()
	resp, body := doReqKey2(t, srv, http.MethodPost, "/api/v1/hooks/definitions", cookie,
		map[string]any{"name": name, "kind": "webhook", "url": url}, "hook-create-key-"+name)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create hook def = %d (%s)", resp.StatusCode, body)
	}
	var d map[string]any
	_ = json.Unmarshal(body, &d)
	return d["id"].(string), d["etag"].(string)
}

// RED P16 Story 3 (i): the hook routes are session-auth required.
func TestHookRoutesRequireAuth(t *testing.T) {
	srv, _, _ := newHooksTestServer(t)
	for _, path := range []string{
		"/api/v1/hooks/definitions",
		"/api/v1/hooks/secrets",
	} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d want 401", path, resp.StatusCode)
		}
	}
	// Retry on a missing delivery still refuses unauthenticated access.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hook-deliveries/x/retry", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("retry unauth: %d want 401", resp.StatusCode)
	}
}

// RED P16 Story 3 (j): hook definition create/list/patch/delete follow ETag
// and Idempotency-Key semantics (201, 409, 428/412, 204).
func TestHookDefinitionCRUD(t *testing.T) {
	srv, st, _ := newHooksTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	id, etag := createHookDef(t, srv, cookie, "web", "https://example.com/hook")

	resp, body := doReq(t, srv, http.MethodGet, "/api/v1/hooks/definitions", cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d (%s)", resp.StatusCode, body)
	}
	var list []map[string]any
	_ = json.Unmarshal(body, &list)
	if len(list) != 1 || list[0]["id"] != id {
		t.Fatalf("list = %s", body)
	}

	// PATCH without If-Match -> 428.
	resp, _ = doReq(t, srv, http.MethodPatch, "/api/v1/hooks/definitions/"+id, cookie, map[string]any{"name": "renamed"})
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("patch missing if-match = %d, want 428", resp.StatusCode)
	}

	// PATCH with stale If-Match -> 412.
	resp, body = doReqIfMatch(t, srv, http.MethodPatch, "/api/v1/hooks/definitions/"+id, cookie, map[string]any{"name": "renamed"}, `"rev-999"`)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("patch stale = %d (%s), want 412", resp.StatusCode, body)
	}

	// PATCH with correct etag -> 200, new etag.
	resp, body = doReqIfMatch(t, srv, http.MethodPatch, "/api/v1/hooks/definitions/"+id, cookie, map[string]any{"name": "renamed"}, etag)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch ok = %d (%s)", resp.StatusCode, body)
	}
	var updated map[string]any
	_ = json.Unmarshal(body, &updated)
	if updated["name"] != "renamed" || updated["etag"] == etag {
		t.Fatalf("patch result = %s", body)
	}

	// DELETE without If-Match -> 428; with correct etag -> 204.
	resp, _ = doReq(t, srv, http.MethodDelete, "/api/v1/hooks/definitions/"+id, cookie, nil)
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("delete missing if-match = %d, want 428", resp.StatusCode)
	}
	resp, _ = doReqIfMatch(t, srv, http.MethodDelete, "/api/v1/hooks/definitions/"+id, cookie, nil, updated["etag"].(string))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", resp.StatusCode)
	}
}

// RED P16 Story 3 (k): creates are Idempotency-Key durable: replaying the same
// key returns the same 201 body; reusing the key with a different request is a
// 409 IDEMPOTENCY_CONFLICT.
func TestHookDefinitionCreateIdempotent(t *testing.T) {
	srv, st, _ := newHooksTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	body := map[string]any{"name": "web", "kind": "webhook", "url": "https://example.com/hook"}
	resp1, b1 := doReqKey2(t, srv, http.MethodPost, "/api/v1/hooks/definitions", cookie, body, "def-key-0001")
	resp2, b2 := doReqKey2(t, srv, http.MethodPost, "/api/v1/hooks/definitions", cookie, body, "def-key-0001")
	if resp1.StatusCode != http.StatusCreated || string(b1) != string(b2) {
		t.Fatalf("idempotent replay mismatch: %d %s vs %d %s", resp1.StatusCode, b1, resp2.StatusCode, b2)
	}
	resp3, b3 := doReqKey2(t, srv, http.MethodPost, "/api/v1/hooks/definitions", cookie,
		map[string]any{"name": "other", "kind": "webhook", "url": "https://other.example/hook"}, "def-key-0001")
	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("conflict reuse = %d (%s), want 409", resp3.StatusCode, b3)
	}
}

// RED P16 Story 3 (l): secret create returns metadata only (never the value)
// and the value is at-rest encrypted; duplicate secret_id -> 409.
func TestHookSecretMetadataOnlyAndAtRest(t *testing.T) {
	srv, st, svc := newHooksTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	resp, body := doReqKey2(t, srv, http.MethodPost, "/api/v1/hooks/secrets", cookie,
		map[string]any{"secret_id": "provider-key", "algorithm": "HMAC-SHA256", "value": "SuperSecretValue"},
		"secret-key-0001")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create secret = %d (%s)", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "SuperSecretValue") {
		t.Fatalf("secret value leaked in create response: %s", body)
	}
	var meta map[string]any
	_ = json.Unmarshal(body, &meta)
	if meta["secret_id"] != "provider-key" || meta["algorithm"] != "HMAC-SHA256" {
		t.Fatalf("secret metadata wrong: %s", body)
	}
	if _, ok := meta["value"]; ok {
		t.Fatalf("secret response contains a value field")
	}
	// List returns metadata only.
	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/hooks/secrets", cookie, nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "SuperSecretValue") {
		t.Fatalf("secret list leaked: %d %s", resp.StatusCode, body)
	}
	// At rest: the stored ciphertext is not the plaintext.
	rows, err := svc.Store.ListSecrets()
	if err != nil || len(rows) != 1 {
		t.Fatalf("store list: %v %d", err, len(rows))
	}
	secretRow, err := svc.Store.GetSecretRow("provider-key")
	if err != nil {
		t.Fatal(err)
	}
	if bytesContains(secretRow.Ciphertext, "SuperSecretValue") {
		t.Fatal("plaintext stored unencrypted at rest")
	}
	// Duplicate secret_id -> 409.
	resp, _ = doReqKey2(t, srv, http.MethodPost, "/api/v1/hooks/secrets", cookie,
		map[string]any{"secret_id": "provider-key", "algorithm": "HMAC-SHA256", "value": "Different"},
		"secret-key-0002")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate secret_id = %d, want 409", resp.StatusCode)
	}
}

func bytesContains(haystack []byte, needle string) bool {
	return strings.Contains(string(haystack), needle)
}

// RED P16 Story 3 (m): the retry route returns a 202 Operation and requeues a
// DLQED delivery as PENDING.
func TestHookDeliveryRetryReturnsOperation(t *testing.T) {
	srv, st, svc := newHooksTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	def, err := svc.CreateDefinition("web", "webhook", "https://example.com/hook")
	if err != nil {
		t.Fatal(err)
	}
	evt := hook.Event{HookID: def.ID, EventID: "evt-retry", Payload: []byte(`{}`),
		Policy: hook.QueuePolicy{Version: 1, OnFull: hook.OnFullDLQ, MaxAttempts: 1}}
	deliv, err := svc.EnqueueLifecycleEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Store.ClaimDue(10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %d", err, len(claimed))
	}
	if err := svc.Store.MarkFailed(deliv.ID, "boom"); err != nil {
		t.Fatal(err)
	}
	svc.SetClock(time.Now)
	resp, body := doReq(t, srv, http.MethodPost, "/api/v1/hook-deliveries/"+deliv.ID+"/retry", cookie, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("retry = %d (%s), want 202", resp.StatusCode, body)
	}
	var op map[string]any
	_ = json.Unmarshal(body, &op)
	if op["operation_id"] == "" || op["state"] == "" {
		t.Fatalf("operation missing: %s", body)
	}
	got, err := svc.Store.GetDelivery(deliv.ID)
	if err != nil || got.State != hook.DeliveryPending {
		t.Fatalf("delivery after retry: %v %+v", err, got)
	}
}
