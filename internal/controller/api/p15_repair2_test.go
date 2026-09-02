package api_test

// P15 repair cycle-2 RED P1-B API tests: traversal-defaults PUT must not enter
// a permanent-412 drift after any other node.rev bump (rename bumps
// nodes.revision; the defaults row used to lag). The fix keeps the If-Match
// CAS axis on nodes.revision so a re-read node ETag PUT succeeds, stale ETags
// stay 412, and the 200 still returns a full Node with a fresh ETag.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestP15Repair2TraversalDefaultsPUTAfterRenameSucceeds(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/nodes", cookie, map[string]any{"name": "td-drift"}, "td-drift-key")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create node = %d (%s)", resp.StatusCode, body)
	}
	var node map[string]any
	_ = json.Unmarshal(body, &node)
	nodeID := node["id"].(string)
	etag0, _ := node["etag"].(string)
	if nodeID == "" || etag0 == "" {
		t.Fatalf("node fields missing: %s", body)
	}

	// (a) fresh node first PUT: 200 + full Node + fresh ETag.
	resp, body = doReqIfMatch(t, srv, http.MethodPut, "/api/v1/nodes/"+nodeID+"/traversal-defaults", cookie,
		map[string]any{"tcp_strategy": "auto"}, etag0)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh defaults PUT = %d (%s)", resp.StatusCode, body)
	}
	var first map[string]any
	_ = json.Unmarshal(body, &first)
	etag1, _ := first["etag"].(string)
	if etag1 == "" || etag1 == etag0 {
		t.Fatalf("fresh defaults PUT ETag must be fresh, got %q", etag1)
	}
	for _, field := range []string{"id", "name", "control_state", "created_at"} {
		if _, ok := first[field]; !ok {
			t.Fatalf("fresh defaults PUT response missing Node field %q: %s", field, body)
		}
	}

	// Rename bumps nodes.revision (node.rev -> etag2).
	resp, body = doReqIfMatch(t, srv, http.MethodPatch, "/api/v1/nodes/"+nodeID, cookie,
		map[string]any{"name": "td-drift-renamed"}, etag1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename node = %d (%s)", resp.StatusCode, body)
	}
	var renamed map[string]any
	_ = json.Unmarshal(body, &renamed)
	etag2, _ := renamed["etag"].(string)
	if etag2 == "" || etag2 == etag1 {
		t.Fatalf("rename ETag must be fresh, got %q", etag2)
	}

	// Stale defaults PUT (pre-rename ETag) is still 412.
	resp, body = doReqIfMatch(t, srv, http.MethodPut, "/api/v1/nodes/"+nodeID+"/traversal-defaults", cookie,
		map[string]any{"tcp_strategy": "auto"}, etag1)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale defaults PUT = %d (%s), want 412", resp.StatusCode, body)
	}

	// (b) the NEW node ETag (post-rename) must succeed. RED: pre-fix this was a
	// permanent 412 because the defaults row revision lagged nodes.revision.
	resp, body = doReqIfMatch(t, srv, http.MethodPut, "/api/v1/nodes/"+nodeID+"/traversal-defaults", cookie,
		map[string]any{"tcp_strategy": "auto", "udp_strategy": "stun-only"}, etag2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("defaults PUT after rename = %d (%s) RED: pre-fix permanent 412", resp.StatusCode, body)
	}
	var updated map[string]any
	_ = json.Unmarshal(body, &updated)
	if updated["etag"] == nil || updated["etag"] == etag2 {
		t.Fatalf("defaults PUT after rename ETag must be fresh: %s", body)
	}
}

// P2-A end-state through the handler: a force delete writes the durable
// operation BEFORE the tombstone, so the returned operation is pollable AND the
// tombstone is correlated to that same operation id (intent-before-side-effect
// leaves no tombstone/outbox without a pollable operation).
func TestP15Repair2ForceDeleteOperationAndTombstoneCorrelated(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	nodeID, _ := createNodeAPI(t, srv, cookie)

	resp, body := doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("force delete = %d (%s)", resp.StatusCode, body)
	}
	var op map[string]any
	_ = json.Unmarshal(body, &op)
	opID, _ := op["operation_id"].(string)
	if opID == "" {
		t.Fatalf("operation_id missing: %s", body)
	}

	// The durable operation row is pollable through the frozen route.
	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/node-deletions/"+opID, cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll force deletion = %d (%s)", resp.StatusCode, body)
	}
	// The terminal fact is correlated to that same operation (not an orphan).
	ts, err := st.NodeCleanupTombstone(nodeID)
	if err != nil {
		t.Fatalf("tombstone lookup = %v", err)
	}
	if ts.OperationID != opID {
		t.Fatalf("tombstone operation = %q, want %q (correlated intent)", ts.OperationID, opID)
	}
	// Normal delete keeps the operation + outbox transaction and never creates a
	// tombstone (P2-A: normal path never quarantines).
	resp, body = doReqKey(t, srv, http.MethodPost, "/api/v1/nodes", cookie, map[string]any{"name": "node-normal-2"}, "node-repair-create-2")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create second node = %d (%s)", resp.StatusCode, body)
	}
	var n2 map[string]any
	_ = json.Unmarshal(body, &n2)
	node2, _ := n2["id"].(string)
	resp, body = doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+node2+"/delete", cookie, map[string]any{"mode": "normal"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("normal delete = %d (%s)", resp.StatusCode, body)
	}
	if cleanup, err := st.IsCleanupOnly(node2); err != nil || cleanup {
		t.Fatalf("normal delete quarantine = %v err %v, want false (never quarantines)", cleanup, err)
	}
}

// RED P2-C through the handler: two concurrent category PATCHes racing for the
// same order_index must resolve to exactly one 200 and one 409 — never a 500
// (the pre-fix UNIQUE race surfaced as INTERNAL_ERROR). Under BEGIN IMMEDIATE
// the loser's pre-check runs after the winner commits and maps to CONFLICT.
func TestP15Repair2NavigationCategoryOrderRaceNever500(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	createCategory := func(name string, order int, key string) (id, etag string) {
		resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/navigation/categories", cookie,
			map[string]any{"name": name, "order_index": order}, key)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create category %s = %d (%s)", name, resp.StatusCode, body)
		}
		var c map[string]any
		_ = json.Unmarshal(body, &c)
		return c["id"].(string), c["etag"].(string)
	}
	idA, etagA := createCategory("nav-a", 1, "nav-cat-key-a-0001")
	idB, etagB := createCategory("nav-b", 2, "nav-cat-key-b-0002")

	statuses := make([]int, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp, _ := doReqIfMatch(t, srv, http.MethodPatch, "/api/v1/navigation/categories/"+idA, cookie,
			map[string]any{"order_index": 99}, etagA)
		statuses[0] = resp.StatusCode
	}()
	go func() {
		defer wg.Done()
		resp, _ := doReqIfMatch(t, srv, http.MethodPatch, "/api/v1/navigation/categories/"+idB, cookie,
			map[string]any{"order_index": 99}, etagB)
		statuses[1] = resp.StatusCode
	}()
	wg.Wait()

	for i, status := range statuses {
		if status != http.StatusOK && status != http.StatusConflict {
			t.Fatalf("writer %d category PATCH = %d, want 200 or 409 (RED: pre-fix 500 on UNIQUE race)", i, status)
		}
	}
	if statuses[0] == statuses[1] {
		t.Fatalf("both category PATCHes = %d/%d: exactly one wins and one conflicts", statuses[0], statuses[1])
	}
}

// RED P2-D (api fallback events route): a credential under the literal "value"
// key is redacted (hook/hook-secret shape) while surrounding data survives.
func TestP15Repair2EventsRedactCredentialValue(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	if _, err := st.AppendAdminEvent("hook-secret", `{"id":"h1","name":"hook-a","value":"dG9wLXNlY3JldA==","safe":"keep"}`); err != nil {
		t.Fatal(err)
	}
	text := readAPIStream(t, srv, cookie)
	if strings.Contains(text, "dG9wLXNlY3JldA") {
		t.Fatalf("credential value leaked through api fallback redaction: %q", text)
	}
	if !strings.Contains(text, `"safe":"keep"`) {
		t.Fatalf("event data must survive api fallback redaction: %q", text)
	}
}

// RED P2-D (api fallback events route): legitimate "value" data is preserved.
func TestP15Repair2EventsPreserveLegitimateValue(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	if _, err := st.AppendAdminEvent("measurement", `{"kind":"signal","value":"stun-only"}`); err != nil {
		t.Fatal(err)
	}
	text := readAPIStream(t, srv, cookie)
	if !strings.Contains(text, `"value":"stun-only"`) {
		t.Fatalf("legitimate value lost to api fallback redaction: %q", text)
	}
}

func readAPIStream(t *testing.T, srv *httptest.Server, cookie *http.Cookie) string {
	t.Helper()
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
	buf := make([]byte, 4096)
	done := make(chan struct{})
	var n int
	go func() {
		n, _ = resp.Body.Read(buf)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout reading event stream")
	}
	return string(buf[:n])
}
