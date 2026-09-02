package api_test

// P15 repair cycle-1 RED H3 API test: node deletion routes normal/force
// through the P14 lifecycle. Pre-fix, both modes wrote a bare node_decommission
// outbox message: force never created the terminal cleanup tombstone and never
// closed an ESTABLISHED session. After the fix, force creates the tombstone
// and fires the App-composed session closer; normal neither tombstones nor
// closes a session; both keep the 202 Operation response and the
// /api/v1/node-deletions polling surface.

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestP15Repair1H3NodeDeleteForceLifecycleAndNormal(t *testing.T) {
	srv, st := newTestServerWithCloser(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	nodeID, _ := createNodeAPI(t, srv, cookie)

	// normal delete: 202 + operation, no tombstone, no session close.
	resp, body := doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "normal"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("normal delete = %d (%s)", resp.StatusCode, body)
	}
	var op map[string]any
	if err := json.Unmarshal(body, &op); err != nil {
		t.Fatal(err)
	}
	normalOpID := op["operation_id"].(string)
	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/node-deletions/"+normalOpID, cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll normal deletion = %d (%s)", resp.StatusCode, body)
	}
	cleanupOnly, err := st.IsCleanupOnly(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if cleanupOnly {
		t.Fatalf("normal delete must not create a cleanup tombstone")
	}
	if closerCalls.Load() != 0 {
		t.Fatalf("normal delete must not close a session, closed=%d", closerCalls.Load())
	}

	// force delete: 202 + operation + cleanup tombstone + session close.
	resp, body = doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("force delete = %d (%s)", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &op); err != nil {
		t.Fatal(err)
	}
	forceOpID := op["operation_id"].(string)
	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/node-deletions/"+forceOpID, cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll force deletion = %d (%s)", resp.StatusCode, body)
	}
	cleanupOnly, err = st.IsCleanupOnly(nodeID)
	if err != nil || !cleanupOnly {
		t.Fatalf("IsCleanupOnly after force = %v err %v, want true", cleanupOnly, err)
	}
	if closerCalls.Load() != 1 {
		t.Fatalf("force delete must close the session exactly once, closed=%d", closerCalls.Load())
	}
}

// RED H3/H6 backstop: a force delete of an already-tombstoned node is refused
// (the terminal fact never forks), leaving no extra operation row.
func TestP15Repair1H3NodeDeleteForceTwiceRefusesSecondTombstone(t *testing.T) {
	srv, st := newTestServerWithCloser(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	nodeID, _ := createNodeAPI(t, srv, cookie)

	resp, _ := doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first force delete = %d", resp.StatusCode)
	}
	resp, _ = doReq(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("second force delete = %d, want 500 (terminal fact never forks)", resp.StatusCode)
	}
}
