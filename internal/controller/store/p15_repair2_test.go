package store_test

// P15 repair cycle-2 RED P1-B: traversal-defaults PUT used the defaults row
// revision (when nonzero) as the If-Match baseline. Any other node.rev bump
// (rename, agent reconnect) left the defaults row lagging the node revision,
// so the next PUT carrying the current node ETag returned ErrCASConflict
// forever — a permanent 412. The durable CAS now lives exclusively on
// nodes.revision; the defaults row is written lockstep with the node.

import (
	"errors"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// (a) fresh node first PUT still succeeds and keeps node/defaults lockstep.
func TestP15Repair2PutTraversalDefaultsFreshNodeStillSucceeds(t *testing.T) {
	s := openRepairStore(t)
	if err := s.CreateNode(store.Node{ID: "node-fresh", Name: "fresh", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	d, err := s.PutTraversalDefaults("node-fresh", "auto", "", 1)
	if err != nil {
		t.Fatalf("fresh defaults PUT = %v, want success", err)
	}
	if d.Revision != 2 {
		t.Fatalf("defaults revision = %d, want 2", d.Revision)
	}
	if n, err := s.GetNode("node-fresh"); err != nil || n.Revision != 2 {
		t.Fatalf("node after PUT = %+v err %v, want revision 2", n, err)
	}
}

// (b) after a rename bump the second defaults PUT with the NEW node ETag
// succeeds; before the fix it was a permanent 412.
func TestP15Repair2PutTraversalDefaultsAfterRenameBumpSucceeds(t *testing.T) {
	s := openRepairStore(t)
	if err := s.CreateNode(store.Node{ID: "node-drift", Name: "drift", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutTraversalDefaults("node-drift", "auto", "", 1); err != nil {
		t.Fatalf("first defaults PUT: %v", err)
	}
	// Rename bumps nodes.revision 2 -> 3.
	if _, err := s.UpdateNodeNameCAS("node-drift", 2, "drift-renamed"); err != nil {
		t.Fatalf("rename node: %v", err)
	}
	// Stale defaults PUT with the pre-rename ETag is a conflict.
	if _, err := s.PutTraversalDefaults("node-drift", "auto", "", 2); !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("stale defaults PUT = %v, want ErrCASConflict", err)
	}
	// The current node ETag (rev 3) must succeed — the CAS axis is nodes.revision.
	got, err := s.PutTraversalDefaults("node-drift", "auto", "stun-only", 3)
	if err != nil {
		t.Fatalf("defaults PUT after rename = %v (RED: pre-fix permanent 412)", err)
	}
	if got.Revision != 4 {
		t.Fatalf("defaults revision = %d, want lockstep 4", got.Revision)
	}
	if n, err := s.GetNode("node-drift"); err != nil || n.Revision != 4 {
		t.Fatalf("node after defaults PUT = %+v err %v, want revision 4", n, err)
	}
}

// (b continued) the agent-reconnect bump (AcquireControlOwner) is the same
// permanent-412 source; it must also stay writable.
func TestP15Repair2PutTraversalDefaultsAfterReconnectBumpSucceeds(t *testing.T) {
	s := openRepairStore(t)
	if err := s.CreateNode(store.Node{ID: "node-reconnect", Name: "reconnect", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutTraversalDefaults("node-reconnect", "auto", "", 1); err != nil {
		t.Fatalf("first defaults PUT: %v", err)
	}
	if _, err := s.AcquireControlOwner("node-reconnect", 0, "sess-reconnect-1"); err != nil {
		t.Fatal(err)
	}
	// node.rev is now 3 (2 -> control owner bump). A fresh-etag PUT must work.
	if _, err := s.PutTraversalDefaults("node-reconnect", "manual-static-v4", "stun-only", 3); err != nil {
		t.Fatalf("defaults PUT after reconnect = %v (RED: pre-fix permanent 412)", err)
	}
	if n, err := s.GetNode("node-reconnect"); err != nil || n.Revision != 4 {
		t.Fatalf("node after reconnect PUT = %+v err %v, want revision 4", n, err)
	}
}

// (c) two concurrent PUTs with the same expected node revision: exactly one
// wins, the other maps to ErrCASConflict (412), and both rows (node + defaults)
// stay in lockstep.
func TestP15Repair2PutTraversalDefaultsConcurrentSingleWinner(t *testing.T) {
	s := openRepairStore(t)
	if err := s.CreateNode(store.Node{ID: "node-race", Name: "race", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	const writers = 2
	results := make([]error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.PutTraversalDefaults("node-race", "auto", "", 1)
			results[i] = err
		}(i)
	}
	wg.Wait()
	winners := 0
	for i, err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, store.ErrCASConflict) {
			t.Fatalf("writer %d error = %v, want nil or ErrCASConflict", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly one (results=%v)", winners, results)
	}
	n, err := s.GetNode("node-race")
	if err != nil || n.Revision != 2 {
		t.Fatalf("node after concurrent PUTs = %+v err %v, want revision 2", n, err)
	}
}

// RED P2-C: UpdateNavigationCategoryCAS pre-checked order_index with a separate
// SELECT and then ran an unconditional UPDATE; two concurrent writers claiming
// the same order_index raced on the UPDATE, and any constraint error surfaced as
// a raw error (500 in the handler) instead of ErrNavigationOrderConflict (409).
// Now serialized under BEGIN IMMEDIATE: exactly one writer wins order 99 and the
// loser maps to ErrNavigationOrderConflict; no duplicate order_index persists.
func TestP15Repair2NavigationCategoryOrderRaceSingleWinner(t *testing.T) {
	s := openRepairStore(t)
	if _, err := s.CreateNavigationCategory(store.NavigationCategory{ID: "cat-a", Name: "A", OrderIndex: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateNavigationCategory(store.NavigationCategory{ID: "cat-b", Name: "B", OrderIndex: 2}); err != nil {
		t.Fatal(err)
	}

	const order = 99
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i, id := range []string{"cat-a", "cat-b"} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			_, err := s.UpdateNavigationCategoryCAS(id, 1, id, order)
			results[i] = err
		}(i, id)
	}
	wg.Wait()

	winners := 0
	for i, err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, store.ErrNavigationOrderConflict) {
			t.Fatalf("writer %d error = %v, want nil or ErrNavigationOrderConflict (RED: pre-fix raw error)", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly one (results=%v)", winners, results)
	}
	// Exactly one category may hold order 99.
	cats, err := s.ListNavigationCategories()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range cats {
		if c.OrderIndex == order {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("categories with order %d = %d, want 1", order, count)
	}
}
