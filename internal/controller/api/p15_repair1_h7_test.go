package api_test

// P15 repair cycle-1 RED H7 API test: force-publish previously changed only
// publication_state, left OPEN_FROM_VANTAGE/VERIFIED axes claiming a verified
// publication, and returned the stale pre-write snapshot. The fixed handler
// clears the verified axes (PUBLISHED_UNVERIFIED must never claim
// OPEN_FROM_VANTAGE) and re-reads fresh state for the 200.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func TestP15Repair1H7ForcePublishClearsVerifiedAxesAndReturnsFresh(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	nodeID, _ := createNodeAPI(t, srv, cookie)
	forwardID := createForwardAPI(t, srv, cookie, nodeID)

	f, err := st.GetForward(forwardID)
	if err != nil {
		t.Fatal(err)
	}
	verified := protocol.ActivationStates{
		ControlState:         "ONLINE",
		ListenerState:        "READY",
		MappingState:         "PUBLIC_CANDIDATE",
		KeepaliveState:       "HEALTHY",
		WanReachabilityState: "OPEN_FROM_VANTAGE",
		ReturnPathState:      "VERIFIED",
		TargetHealthState:    "PASS",
		PublicationState:     "PUBLISHED_VERIFIED",
		DataPlaneState:       "READY",
	}
	raw, err := json.Marshal(verified)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetForwardRuntimeStatus(forwardID, f.CurrentActivationID, f.Revision, string(raw)); err != nil {
		t.Fatalf("seed runtime status: %v", err)
	}
	etag := mustETag(t, srv, cookie, forwardID)

	resp, body := doReqIfMatch(t, srv, http.MethodPost, "/api/v1/forwards/"+forwardID+"/force-publish", cookie, nil, etag)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("force-publish = %d (%s)", resp.StatusCode, body)
	}
	var view map[string]any
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	states, _ := view["states"].(map[string]any)
	if states["publication_state"] != "PUBLISHED_UNVERIFIED" {
		t.Fatalf("publication_state = %v, want PUBLISHED_UNVERIFIED (%s)", states["publication_state"], body)
	}
	if states["wan_reachability_state"] == "OPEN_FROM_VANTAGE" {
		t.Fatalf("wan_reachability_state still claims OPEN_FROM_VANTAGE after force publish: %s", body)
	}
	if states["return_path_state"] == "VERIFIED" {
		t.Fatalf("return_path_state still claims VERIFIED after force publish: %s", body)
	}

	// The GET returns the same fresh state.
	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/forwards/"+forwardID, cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get forward = %d (%s)", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &view)
	states, _ = view["states"].(map[string]any)
	if states["publication_state"] != "PUBLISHED_UNVERIFIED" {
		t.Fatalf("post-publish GET publication_state = %v, want PUBLISHED_UNVERIFIED", states["publication_state"])
	}
}
