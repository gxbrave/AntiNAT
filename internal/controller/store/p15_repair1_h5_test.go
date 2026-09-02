package store_test

// P15 repair cycle-1 RED H5 store tests: ListNodes()/ListForwards() previously
// ignored page/page_size/sort/filter and returned the full set in id order, so
// a sort or filter had no effect and total was wrong. ListNodePage/
// ListForwardPage now enforce the frozen quota.

import (
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair1H5NodePageSortFilterTotal(t *testing.T) {
	s := openRepairStore(t)
	for _, n := range []store.Node{
		{ID: "n1", Name: "alpha", ControlState: "ONLINE"},
		{ID: "n2", Name: "beta", ControlState: "OFFLINE"},
		{ID: "n3", Name: "gamma", ControlState: "ONLINE"},
	} {
		if err := s.CreateNode(n); err != nil {
			t.Fatal(err)
		}
	}
	paged, total, err := s.ListNodePage(store.ListQuery{Page: 1, PageSize: 2, Sort: "name"})
	if err != nil {
		t.Fatalf("ListNodesPage: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(paged) != 2 || paged[0].Name != "alpha" || paged[1].Name != "beta" {
		t.Fatalf("page(names asc) = %+v, want [alpha beta]", paged)
	}
	paged, total, err = s.ListNodePage(store.ListQuery{Page: 2, PageSize: 2, Sort: "name"})
	if err != nil || total != 3 || len(paged) != 1 || paged[0].Name != "gamma" {
		t.Fatalf("page2 = %+v total %d err %v, want [gamma]", paged, total, err)
	}
	paged, total, err = s.ListNodePage(store.ListQuery{Page: 1, PageSize: 10, Sort: "-name"})
	if err != nil || len(paged) != 3 || paged[0].Name != "gamma" || paged[2].Name != "alpha" {
		t.Fatalf("sort -name = %+v err %v", paged, err)
	}
	paged, total, err = s.ListNodePage(store.ListQuery{Page: 1, PageSize: 10, Filter: "state=ONLINE"})
	if err != nil || total != 2 || len(paged) != 2 {
		t.Fatalf("filter state=ONLINE = %+v total %d err %v, want 2 ONLINE", paged, total, err)
	}
	if _, _, err := s.ListNodePage(store.ListQuery{Page: 1, PageSize: 10, Sort: "bogus"}); !errors.Is(err, store.ErrInvalidListQuery) {
		t.Fatalf("unknown sort err = %v, want ErrInvalidListQuery", err)
	}
	if _, _, err := s.ListNodePage(store.ListQuery{Page: 1, PageSize: 10, Filter: "bogus=1"}); !errors.Is(err, store.ErrInvalidListQuery) {
		t.Fatalf("unknown filter err = %v, want ErrInvalidListQuery", err)
	}
}

func TestP15Repair1H5ForwardPageSortFilterTotal(t *testing.T) {
	s := openRepairStore(t)
	mustNodeRepair(t, s, "node-f")
	for _, f := range []store.Forward{
		{ID: "f1", NodeID: "node-f", Name: "web", Protocol: "tcp"},
		{ID: "f2", NodeID: "node-f", Name: "dns", Protocol: "udp"},
		{ID: "f3", NodeID: "node-f", Name: "ssh", Protocol: "tcp"},
	} {
		if _, err := s.CreateForward(f); err != nil {
			t.Fatal(err)
		}
	}
	paged, total, err := s.ListForwardPage(store.ListQuery{Page: 1, PageSize: 2, Sort: "-name"})
	if err != nil || total != 3 {
		t.Fatalf("forward page = %+v total %d err %v", paged, total, err)
	}
	if len(paged) != 2 || paged[0].Name != "web" || paged[1].Name != "ssh" {
		t.Fatalf("forward sort -name page = %+v, want [web ssh]", paged)
	}
	paged, total, err = s.ListForwardPage(store.ListQuery{Page: 1, PageSize: 10, Filter: "protocol=tcp"})
	if err != nil || total != 2 || len(paged) != 2 {
		t.Fatalf("filter protocol=tcp = %+v total %d err %v", paged, total, err)
	}
}
