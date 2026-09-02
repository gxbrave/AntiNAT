package api_test

// P15 repair cycle-2 RED P1-B API tests: traversal-defaults PUT must not enter
// a permanent-412 drift after any other node.rev bump (rename bumps
// nodes.revision; the defaults row used to lag). The fix keeps the If-Match
// CAS axis on nodes.revision so a re-read node ETag PUT succeeds, stale ETags
// stay 412, and the 200 still returns a full Node with a fresh ETag.

import (
	"encoding/json"
	"net/http"
	"testing"
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
