package api_test

// P15 repair cycle-1 RED H5 API test: the nodes list ignored
// page/page_size/sort/filter and always reported page=1 with total=len(items).
// The fixed handler honors the frozen params and rejects unknown sort fields
// with 400.

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestP15Repair1H5NodesListPaginationSortFilter(t *testing.T) {
	srv, st := newTestServer(t)
	user, pass := initAdmin(t, srv, st)
	cookie := login(t, srv, user, pass)

	for i := 0; i < 3; i++ {
		resp, body := doReqKey(t, srv, http.MethodPost, "/api/v1/nodes", cookie,
			map[string]any{"name": "node-" + string(rune('a'+i))}, "node-list-key-"+string(rune('a'+i)))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create node %d = %d (%s)", i, resp.StatusCode, body)
		}
	}

	resp, body := doReq(t, srv, http.MethodGet, "/api/v1/nodes?page_size=2&sort=-created_at", cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list nodes = %d (%s)", resp.StatusCode, body)
	}
	var page map[string]any
	_ = json.Unmarshal(body, &page)
	if page["page"] != float64(1) || page["page_size"] != float64(2) || page["total"] != float64(3) {
		t.Fatalf("node page metadata = %s, want page=1 size=2 total=3", body)
	}
	items, _ := page["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("node page items = %d, want 2", len(items))
	}

	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/nodes?filter=state=OFFLINE&page_size=50", cookie, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filtered nodes = %d (%s)", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &page)
	if page["total"] != float64(3) {
		t.Fatalf("filter state=OFFLINE total = %v, want 3 (%s)", page["total"], body)
	}

	resp, body = doReq(t, srv, http.MethodGet, "/api/v1/nodes?sort=bogus", cookie, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid sort = %d (%s), want 400", resp.StatusCode, body)
	}
}
