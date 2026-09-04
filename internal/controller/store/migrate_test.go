package store_test

import (
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED 1a: opening a fresh database applies every owned migration and
// reports the resulting schema version.
func TestOpenAppliesAllMigrations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	version, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != 11 {
		t.Fatalf("SchemaVersion = %d, want 11 (P17 0011_deployment)", version)
	}
}

// RED 1b: reopening an already-migrated database is a no-op (idempotent).
func TestOpenIsIdempotentAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")

	s1, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()

	version, err := s2.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion after reopen: %v", err)
	}
	if version != 11 {
		t.Fatalf("SchemaVersion after reopen = %d, want 11", version)
	}
}

// RED 1c: foreign keys are enforced; a forward referencing a missing node
// parent is rejected.
func TestForeignKeysEnforcedForForwardParent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	f := store.Forward{
		ID:       "fwd-1",
		NodeID:   "node-does-not-exist",
		Name:     "web",
		Protocol: "tcp",
	}
	if _, err := s.CreateForward(f); err == nil {
		t.Fatal("CreateForward with missing node parent succeeded, want FK violation")
	}
}

// RED 1d: a forward deletion operation is a logical record that survives the
// cascade deletion of its forward row (frozen state-model §4).
func TestForwardDeletionOperationSurvivesForwardDeletion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	node := store.Node{ID: "node-1", Name: "n1"}
	if err := s.CreateNode(node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	fwd, err := s.CreateForward(store.Forward{
		ID: "fwd-1", NodeID: "node-1", Name: "web", Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("CreateForward: %v", err)
	}
	op := store.ForwardDeletionOperation{
		ID: "delop-1", ForwardID: fwd.ID, Status: "PENDING", DesiredRevision: 1,
	}
	if err := s.CreateForwardDeletionOperation(op); err != nil {
		t.Fatalf("CreateForwardDeletionOperation: %v", err)
	}

	if err := s.DeleteForwardRow(fwd.ID); err != nil {
		t.Fatalf("DeleteForwardRow: %v", err)
	}

	got, err := s.GetForwardDeletionOperation(op.ID)
	if err != nil {
		t.Fatalf("GetForwardDeletionOperation after forward deletion: %v", err)
	}
	if got.ForwardID != fwd.ID || got.Status != "PENDING" {
		t.Fatalf("deletion operation mutated by forward cascade: %+v", got)
	}
}

// RED 1f: a forward spec requires a stable forwards parent; inserting a spec
// for a missing forward is rejected by the foreign key.
func TestForwardSpecRequiresStableForwardParent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	node := store.Node{ID: "node-1", Name: "n1"}
	if err := s.CreateNode(node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	fwd, err := s.CreateForward(store.Forward{
		ID: "fwd-1", NodeID: "node-1", Name: "web", Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("CreateForward: %v", err)
	}

	if err := s.CreateForwardSpec(store.ForwardSpec{
		ID: "spec-1", ForwardID: "fwd-missing", Revision: 1,
		SpecJSON: `{"name":"web"}`,
	}); err == nil {
		t.Fatal("CreateForwardSpec with missing forward parent succeeded, want FK violation")
	}

	if err := s.CreateForwardSpec(store.ForwardSpec{
		ID: "spec-1", ForwardID: fwd.ID, Revision: 1,
		SpecJSON: `{"name":"web"}`,
	}); err != nil {
		t.Fatalf("CreateForwardSpec with valid parent: %v", err)
	}
}

// RED 1e: forwards.current_activation_id advances only under a matching
// revision (transactional CAS); a stale revision is rejected.
func TestForwardActivationCASConflictsOnStaleRevision(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	node := store.Node{ID: "node-1", Name: "n1"}
	if err := s.CreateNode(node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	fwd, err := s.CreateForward(store.Forward{
		ID: "fwd-1", NodeID: "node-1", Name: "web", Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("CreateForward: %v", err)
	}
	if fwd.Revision != 0 {
		t.Fatalf("fresh forward revision = %d, want 0", fwd.Revision)
	}

	if err := s.CASForwardActivation(fwd.ID, 0, "act-1"); err != nil {
		t.Fatalf("CAS with current revision: %v", err)
	}
	after, err := s.GetForward(fwd.ID)
	if err != nil {
		t.Fatalf("GetForward: %v", err)
	}
	if after.CurrentActivationID != "act-1" || after.Revision != 1 {
		t.Fatalf("after CAS = %+v, want activation act-1 revision 1", after)
	}

	if err := s.CASForwardActivation(fwd.ID, 0, "act-2"); err == nil {
		t.Fatal("stale CAS (expected revision 0 after bump to 1) succeeded, want conflict")
	}
	still, err := s.GetForward(fwd.ID)
	if err != nil {
		t.Fatalf("GetForward: %v", err)
	}
	if still.CurrentActivationID != "act-1" || still.Revision != 1 {
		t.Fatalf("failed CAS mutated state: %+v", still)
	}
}
