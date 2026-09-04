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
	nodeID, nodeETag := createNodeAPI(t, srv, cookie)

	// normal delete: 202 + operation, no tombstone, no session close.
	resp, body := doReqIfMatch(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "normal"}, nodeETag)
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
	resp, body = doReqIfMatch(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"}, nodeETag)
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

// repair-2 P2-B: a second force delete of an already-tombstoned node is an
// idempotent re-entry — 202 returning the SAME correlated operation (repeatable
// and pollable), never a fresh operation id nor a 500 INTERNAL_ERROR. The
// terminal fact never forks; the second request converges on the first.
func TestP15Repair2NodeDeleteForceTwiceIsIdempotent202(t *testing.T) {
	srv, st := newTestServerWithCloser(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)
	nodeID, nodeETag := createNodeAPI(t, srv, cookie)

	resp, body := doReqIfMatch(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"}, nodeETag)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first force delete = %d (%s)", resp.StatusCode, body)
	}
	var firstOp map[string]any
	if err := json.Unmarshal(body, &firstOp); err != nil {
		t.Fatal(err)
	}
	firstID := firstOp["operation_id"].(string)

	// Second force delete must NOT be 500: it is an idempotent repeat returning
	// the same operation id.
	resp, body = doReqIfMatch(t, srv, http.MethodPost, "/api/v1/nodes/"+nodeID+"/delete", cookie, map[string]any{"mode": "force"}, nodeETag)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("second force delete = %d (%s), want 202 (RED: pre-fix 500)", resp.StatusCode, body)
	}
	var secondOp map[string]any
	if err := json.Unmarshal(body, &secondOp); err != nil {
		t.Fatal(err)
	}
	if secondOp["operation_id"] != firstID {
		t.Fatalf("second force delete returned operation %v, want the existing %q (idempotent re-entry)", secondOp["operation_id"], firstID)
	}
	// Exactly one operation row and one tombstone survive.
	if _, err := st.GetNodeDeletionOperation(firstID); err != nil {
		t.Fatalf("existing operation not pollable: %v", err)
	}
	if cleanup, err := st.IsCleanupOnly(nodeID); err != nil || !cleanup {
		t.Fatalf("IsCleanupOnly after force = %v err %v, want true", cleanup, err)
	}
	if n, _ := st.ControlOutboxCount(nodeID); n != 1 {
		t.Fatalf("outbox count = %d, want 1 (no forked decommission row)", n)
	}
}
