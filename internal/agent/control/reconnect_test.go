// P08 Story 5 RED: reconnect and semantic resend. After a disconnect the
// agent re-handshakes (higher epoch), requeues un-receipted results, and
// re-envelopes the SAME operation without repeating the side effect; the
// controller re-delivers un-receipted commands without a second apply.
package control_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED 5h: disconnect after the result was queued but before the receipt —
// the reconnect re-envelopes the same semantic result; the handler runs
// exactly once and the controller outbox row is GC'd.
func TestReconnectResendsResultWithoutDuplicateSideEffect(t *testing.T) {
	h := newSessionHarness(t)
	var applied atomic.Int32
	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(ctx context.Context, op control.Operation) ([]byte, error) {
			applied.Add(1)
			return []byte(`{"applied":true}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Enqueue two commands; the first is processed, then we hard-kill the
	// agent connection before the receipt completes, forcing a reconnect.
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-1", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: `{"node_id":"` + h.nodeID + `","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-2", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: `{"node_id":"` + h.nodeID + `","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Wait for the first apply, then kill the socket.
	deadline := time.Now().Add(5 * time.Second)
	for applied.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if applied.Load() == 0 {
		t.Fatal("no command applied before kill")
	}
	client.Close() // hard disconnect (receipt may or may not have landed)

	// Reconnect: new epoch, outbox requeued, same results re-enveloped.
	client2, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(ctx context.Context, op control.Operation) ([]byte, error) {
			applied.Add(1)
			return []byte(`{"applied":true}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("reconnect Connect: %v", err)
	}

	// Both outbox rows must be receipted (GC'd) on the controller.
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, err1 := h.st.ControlOutboxItemByOperation("op-1", "desired")
		_, err2 := h.st.ControlOutboxItemByOperation("op-2", "desired")
		if errors.Is(err1, store.ErrNotFound) && errors.Is(err2, store.ErrNotFound) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := h.st.ControlOutboxItemByOperation("op-1", "desired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("op-1 not receipted after reconnect: %v", err)
	}
	if _, err := h.st.ControlOutboxItemByOperation("op-2", "desired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("op-2 not receipted after reconnect: %v", err)
	}
	// Exactly two side effects across the reconnect (one per operation).
	if got := applied.Load(); got != 2 {
		t.Fatalf("applied = %d, want exactly 2 (no duplicate side effect on resend)", got)
	}
}

// RED 5i: reconnect bumps the agent's persisted epoch and the controller's.
func TestReconnectBumpsEpoch(t *testing.T) {
	h := newSessionHarness(t)
	client, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	epoch1, _, _ := h.ls.CurrentSession()
	client.Close()

	client2, err := control.NewClient(control.ClientOptions{
		Endpoint:  h.srv.URL,
		NodeID:    h.nodeID,
		Store:     h.ls,
		Key:       h.key,
		Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	epoch2, session2, _ := h.ls.CurrentSession()
	if epoch2 != epoch1+1 {
		t.Fatalf("epoch after reconnect = %d, want %d", epoch2, epoch1+1)
	}
	if session2 == "" {
		t.Fatal("empty session after reconnect")
	}
}

var _ = websocket.MessageBinary
