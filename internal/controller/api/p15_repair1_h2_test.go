package api_test

// P15 repair cycle-1 RED H2 API test: traversal-defaults PUT on a fresh node
// (defaults rev 0, node rev 1) previously returned a permanent 412 and, even
// on non-fresh success paths, responded with the wrong {tcp,udp} schema
// instead of a full Node with a fresh ETag.

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestP15Repair1H2TraversalDefaultsFreshNodePUT(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/nodes", cookie, map[string]any{"name": "td-node"}, "td-node-create-key")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create node = %d (%s)", resp.StatusCode, body)
	}
	var node map[string]any
	_ = json.Unmarshal(body, &node)
	nodeID := node["id"].(string)
	etag0 := node["etag"].(string)

	// Bump the node revision to 1 so the fresh-defaults baseline (0) differs
	// from the node revision as the reviewer's RED describes.
	resp, body = doReqIfMatch(t, srv, http.MethodPatch, "/api/v1/nodes/"+nodeID, cookie, map[string]any{"name": "td-node-renamed"}, etag0)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename node = %d (%s)", resp.StatusCode, body)
	}
	var renamed map[string]any
	_ = json.Unmarshal(body, &renamed)
	etag1 := renamed["etag"].(string)

	resp, body = doReqIfMatch(t, srv, http.MethodPut, "/api/v1/nodes/"+nodeID+"/traversal-defaults", cookie,
		map[string]any{"tcp_strategy": "auto", "udp_strategy": "stun-only"}, etag1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh traversal-defaults PUT = %d (%s), want 200 (RED: pre-fix 412)", resp.StatusCode, body)
	}
	var updated map[string]any
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("decode traversal-defaults response: %v body=%s", err, body)
	}
	for _, field := range []string{"id", "name", "control_state", "created_at", "etag"} {
		if _, ok := updated[field]; !ok {
			t.Fatalf("traversal-defaults response missing Node field %q: %s", field, body)
		}
	}
	if updated["etag"] == etag1 {
		t.Fatalf("traversal-defaults response ETag must be fresh, got %v (old %s)", updated["etag"], etag1)
	}

	// Stale PUT (old node ETag) is 412.
	resp, body = doReqIfMatch(t, srv, http.MethodPut, "/api/v1/nodes/"+nodeID+"/traversal-defaults", cookie,
		map[string]any{"tcp_strategy": "auto"}, etag1)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale traversal-defaults PUT = %d (%s), want 412", resp.StatusCode, body)
	}
}
