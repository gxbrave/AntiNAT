// P14 repair-1 H1 (RED): the four lifecycle command types added by P14
// Story 4/5 — key_rotation_prepare, key_rotation_commit, restore_reconcile,
// restore_result — must reach the agent's OnCommand over a REAL signed-session
// frame. Before the fix they fell through the session dispatch switch to the
// default "unexpected message type" arm, which tore the session down, so the
// Agent-side OnCommand hook (app.go handleCommand) implementing them was dead
// code unreachable over the control transport.
package control_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestSessionLifecycleCommandTypesDeliveredOverWire(t *testing.T) {
	h := newSessionHarness(t)

	type counter struct {
		mu  sync.Mutex
		got map[string]int
	}
	seen := &counter{got: make(map[string]int)}

	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(_ context.Context, op control.Operation) ([]byte, error) {
			seen.mu.Lock()
			seen.got[op.MessageType]++
			seen.mu.Unlock()
			return []byte(`{"status":"ok"}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	types := []string{"key_rotation_prepare", "key_rotation_commit", "restore_reconcile", "restore_result"}
	for i, mt := range types {
		item := store.ControlOutboxItem{
			OperationID:     fmt.Sprintf("lc-op-%d", i),
			MessageType:     mt,
			NodeID:          h.nodeID,
			SemanticPayload: `{"controller_instance_id":"inst-1","scope":"controller"}`,
		}
		if err := h.st.EnqueueControlOutbox(item); err != nil {
			t.Fatalf("enqueue %s: %v", mt, err)
		}
	}

	deadline := time.Now().Add(8 * time.Second)
	for {
		seen.mu.Lock()
		n := len(seen.got)
		seen.mu.Unlock()
		if n == len(types) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	seen.mu.Lock()
	defer seen.mu.Unlock()
	for _, mt := range types {
		if seen.got[mt] == 0 {
			t.Fatalf("OnCommand was never invoked for %q over a real signed-session frame (session torn down?)", mt)
		}
	}
}