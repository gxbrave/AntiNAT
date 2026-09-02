package api_test

// P15 repair cycle-1 RED H4 API tests: navigation category/items POST
// previously only validated the Idempotency-Key format; replayed keys created
// duplicate rows and different bodies under the same key were silently
// accepted. The fix persists durable idempotency (BEGIN IMMEDIATE replay/
// conflict authority).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair1H4NavigationCategoryIdempotentCreate(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	do := func(name string) (int, []byte) {
		resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/navigation/categories", cookie, map[string]any{"name": name}, "nav-cat-key-0001")
		return resp.StatusCode, body
	}
	status, first := do("home")
	if status != http.StatusCreated {
		t.Fatalf("first category create = %d (%s)", status, first)
	}
	status, replay := do("home")
	if status != http.StatusCreated {
		t.Fatalf("category replay = %d (%s), want 201", status, replay)
	}
	var a, b map[string]any
	_ = json.Unmarshal(first, &a)
	_ = json.Unmarshal(replay, &b)
	if a["id"] != b["id"] {
		t.Fatalf("replay created a different category: first=%s replay=%s", first, replay)
	}
	resp, conflict := doReqKey(t, srv, http.MethodPost, "/api/v1/navigation/categories", cookie, map[string]any{"name": "other"}, "nav-cat-key-0001")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(conflict), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("different-body category reuse = %d (%s), want 409 IDEMPOTENCY_CONFLICT", resp.StatusCode, conflict)
	}
}

func TestP15Repair1H4NavigationItemIdempotentCreate(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	nodeID, _ := createNodeAPI(t, srv, cookie)
	forwardID := createForwardAPI(t, srv, cookie, nodeID)
	if _, err := st.CreateNavigationCategory(store.NavigationCategory{ID: "cat-1", Name: "cat", OrderIndex: 0}); err != nil {
		t.Fatal(err)
	}

	body := map[string]any{"name": "home-page", "category_id": "cat-1", "forward_id": forwardID, "order_index": 0}
	respI, first := doReqKey(t, srv, http.MethodPost, "/api/v1/navigation/items", cookie, body, "nav-item-key-0001")
	if respI.StatusCode != http.StatusCreated {
		t.Fatalf("first item create = %d (%s)", respI.StatusCode, first)
	}
	respI, replay := doReqKey(t, srv, http.MethodPost, "/api/v1/navigation/items", cookie, body, "nav-item-key-0001")
	if respI.StatusCode != http.StatusCreated {
		t.Fatalf("item replay = %d (%s), want 201", respI.StatusCode, replay)
	}
	var a, b map[string]any
	_ = json.Unmarshal(first, &a)
	_ = json.Unmarshal(replay, &b)
	if a["id"] != b["id"] {
		t.Fatalf("item replay created a different row: %s vs %s", first, replay)
	}
}
