package store_test

// P15 repair cycle-1 RED H2 store test: a fresh node (no traversal-defaults
// record, node revision 1) PUT previously compared the missing defaults
// revision 0 against node revision 1 and returned a permanent 412; a later
// success also returned the wrong {tcp,udp} schema instead of bumping the node
// revision as the durable CAS does today.

import (
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair1H2PutTraversalDefaultsFreshNodeAndCAS(t *testing.T) {
	s := openRepairStore(t)
	if err := s.CreateNode(store.Node{ID: "node-td", Name: "td", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	d, err := s.PutTraversalDefaults("node-td", "auto", "", 1)
	if err != nil {
		t.Fatalf("fresh node traversal-defaults PUT must succeed: %v", err)
	}
	if d.Revision != 2 {
		t.Fatalf("defaults revision = %d, want 2", d.Revision)
	}
	got, err := s.GetNode("node-td")
	if err != nil || got.Revision != 2 {
		t.Fatalf("node revision after defaults PUT = %+v err %v, want 2", got, err)
	}
	if _, err := s.PutTraversalDefaults("node-td", "auto", "", 1); !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("stale defaults PUT = %v, want ErrCASConflict", err)
	}
}
