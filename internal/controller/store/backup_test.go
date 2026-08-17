package store_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED 5a: concurrent WAL writers complete without lost rows while a VACUUM
// INTO backup is taken; the backup opens with a clean integrity check and
// contains every write committed before the backup started.
func TestConcurrentWALWritesAndBackupRestore(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	node := store.Node{ID: "node-1", Name: "n1"}
	if err := s.CreateNode(node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	// Phase 1: writes committed before the backup begins (must all be present
	// in the consistent snapshot).
	pre := 5
	for i := 0; i < pre; i++ {
		if _, err := s.CreateForward(store.Forward{
			ID: fmt.Sprintf("pre-%d", i), NodeID: "node-1",
			Name: fmt.Sprintf("pre-%d", i), Protocol: "tcp",
		}); err != nil {
			t.Fatalf("phase-1 CreateForward: %v", err)
		}
	}

	// Phase 2+3: writers race with the backup.
	var wg sync.WaitGroup
	workers := 6
	per := 10
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < per; j++ {
				if _, err := s.CreateForward(store.Forward{
					ID: fmt.Sprintf("w%d-%d", w, j), NodeID: "node-1",
					Name: fmt.Sprintf("w%d-%d", w, j), Protocol: "tcp",
				}); err != nil {
					t.Errorf("concurrent CreateForward: %v", err)
					return
				}
			}
		}(w)
	}

	backupDir := filepath.Join(t.TempDir(), "backup")
	manifest, err := s.BackupTo(backupDir)
	if err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	if manifest.ControllerInstanceID == "" || manifest.SchemaVersion != 5 {
		t.Fatalf("returned manifest incomplete: %+v", manifest)
	}
	wg.Wait()

	total := pre + workers*per
	got, err := s.ForwardCount()
	if err != nil {
		t.Fatalf("ForwardCount: %v", err)
	}
	if got != total {
		t.Fatalf("ForwardCount = %d, want %d (no lost rows)", got, total)
	}

	// The backup is consistent: it contains at least the phase-1 writes and no
	// more than the total, and opens with a clean integrity/foreign-key check.
	bs, m, err := store.OpenBackup(backupDir)
	if err != nil {
		t.Fatalf("OpenBackup: %v", err)
	}
	defer bs.Close()
	if m.SchemaVersion != 6 {
		t.Fatalf("backup schema version = %d, want 6", m.SchemaVersion)
	}
	if m.ControllerInstanceID == "" {
		t.Fatal("backup manifest missing controller instance id")
	}
	bcount, err := bs.ForwardCount()
	if err != nil {
		t.Fatalf("backup ForwardCount: %v", err)
	}
	if bcount < pre || bcount > total {
		t.Fatalf("backup forward count = %d, want in [%d, %d]", bcount, pre, total)
	}

	// Restore: copy the backup DB to a live path and open it as a normal store.
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	data, err := os.ReadFile(filepath.Join(backupDir, "controller.db"))
	if err != nil {
		t.Fatalf("read backup db: %v", err)
	}
	if err := os.WriteFile(restoredPath, data, 0o600); err != nil {
		t.Fatalf("copy backup db: %v", err)
	}
	rs, err := store.Open(restoredPath)
	if err != nil {
		t.Fatalf("restore Open: %v", err)
	}
	defer rs.Close()
	rcount, err := rs.ForwardCount()
	if err != nil {
		t.Fatalf("restored ForwardCount: %v", err)
	}
	if rcount != bcount {
		t.Fatalf("restored count = %d, want %d", rcount, bcount)
	}
}

// RED 5b: the controller instance id is durable across store restarts (needed
// by backup manifests for anti-rollback, frozen §7.4).
func TestInstanceIDStableAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id1, err := s.InstanceID()
	if err != nil {
		t.Fatalf("InstanceID: %v", err)
	}
	if len(id1) < 16 {
		t.Fatalf("instance id too short: %q", id1)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	id2, err := s2.InstanceID()
	if err != nil {
		t.Fatalf("InstanceID after reopen: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("instance id changed across restart: %q != %q", id1, id2)
	}
}

// RED 5c: free-space reporting works against the real filesystem.
func TestDiskFreeBytesReportsPositive(t *testing.T) {
	free, err := store.DiskFreeBytes(t.TempDir())
	if err != nil {
		t.Fatalf("DiskFreeBytes: %v", err)
	}
	if free == 0 {
		t.Fatal("DiskFreeBytes reported 0 free bytes")
	}
}

// RED 5d: when free space drops below the policy threshold, growth writes are
// refused with ErrDiskLow while delete/decommission operations still succeed
// (stop/delete priority under low-disk pressure, v0.8 §9.1).
func TestLowDiskRefusesGrowthButAllowsDelete(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
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

	// Simulate a full disk.
	s.SetDiskPolicy(1<<40, func(string) (uint64, error) { return 0, nil })

	if _, err := s.CreateForward(store.Forward{
		ID: "fwd-2", NodeID: "node-1", Name: "web2", Protocol: "tcp",
	}); !errors.Is(err, store.ErrDiskLow) {
		t.Fatalf("CreateForward under low disk = %v, want ErrDiskLow", err)
	}
	if err := s.CreateNode(store.Node{ID: "node-2", Name: "n2"}); !errors.Is(err, store.ErrDiskLow) {
		t.Fatalf("CreateNode under low disk = %v, want ErrDiskLow", err)
	}

	// Deletes are priority and must still commit even on a full disk.
	if err := s.ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: "delop-1", ForwardID: fwd.ID, Status: "PENDING", DesiredRevision: fwd.Revision,
	}, store.ControlOutboxItem{
		OperationID: "delop-1", MessageType: "C2A_FORWARD_DELETE",
		NodeID: "node-1", SemanticPayload: `{"forward_id":"fwd-1"}`,
	}); err != nil {
		t.Fatalf("ApplyForwardDelete under low disk = %v, want success (priority)", err)
	}
	if _, err := s.GetForwardDeletionOperation("delop-1"); err != nil {
		t.Fatalf("deletion operation not persisted under low disk: %v", err)
	}
}
