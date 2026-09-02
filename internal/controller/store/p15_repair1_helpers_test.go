package store_test

import (
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func openRepairStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustNodeRepair(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if err := s.CreateNode(store.Node{ID: id, Name: id}); err != nil {
		t.Fatalf("CreateNode(%s): %v", id, err)
	}
}
