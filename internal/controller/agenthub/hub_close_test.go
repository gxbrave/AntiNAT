package agenthub_test

import (
	"context"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// TestHubCloseDrainsActiveSessions covers controller shutdown while an agent
// WebSocket is active. Hub.Close must close the socket and unregister the
// session before the controller store is torn down.
func TestHubCloseDrainsActiveSessions(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-close"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	if err := hub.Close(); err != nil {
		t.Fatalf("Hub.Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := conn.conn.Read(ctx); err == nil {
		t.Fatal("Hub.Close left the active WebSocket open")
	}
	node, err := st.GetNode(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if node.ControlState != "OFFLINE" {
		t.Fatalf("node control state = %q, want OFFLINE after Hub.Close", node.ControlState)
	}
}
