package controller

// P15 repair cycle-1 RED H3b App test: before the App node-deletion watcher, a
// RECEIVED node_decommission_ack left the node deletion operation PENDING
// forever. The watcher advances it to COMPLETED and confirms a force tombstone.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestP15Repair1AppNodeDeletionWatcherCompletesOperation(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown(t.Context())

	s := app.Store()
	if err := s.CreateNode(store.Node{ID: "node-watcher", Name: "watcher"}); err != nil {
		t.Fatal(err)
	}
	owner, err := s.AcquireControlOwner("node-watcher", 0, "sess-watcher-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNodeDeletionOperation(store.NodeDeletionOperation{ID: "nodedel-watcher", NodeID: "node-watcher", Status: "PENDING", Mode: "force"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{NodeID: "node-watcher", OperationID: "nodedel-watcher", Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordControlInboxOwned(owner, store.ControlInboxItem{
		MessageID: "ack-watcher-1", NodeID: "node-watcher", MessageType: "node_decommission_ack",
		OperationID:     "nodedel-watcher",
		SemanticPayload: `{"node_id":"node-watcher","decommission_operation_id":"nodedel-watcher","status":"DECOMMISSIONED","force":true}`,
	}); err != nil {
		t.Fatal(err)
	}

	app.completeNodeDeletions()

	got, err := s.GetNodeDeletionOperation("nodedel-watcher")
	if err != nil || got.Status != "COMPLETED" {
		t.Fatalf("operation after watcher = %+v err %v, want COMPLETED", got, err)
	}
	ts, err := s.NodeCleanupTombstone("node-watcher")
	if err != nil || !ts.RemoteCleanupConfirmed {
		t.Fatalf("tombstone confirmed = %+v err %v, want confirmed", ts, err)
	}
}
