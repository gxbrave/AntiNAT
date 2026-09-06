package agenthub_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// TestNilProbeSinkRecordsProbeResultAndKeepsHeartbeatAlive proves that a
// transport-only Hub may durably retain an authenticated probe_result without
// a configured consumer, while the same control session continues to accept
// heartbeat traffic.
func TestNilProbeSinkRecordsProbeResultAndKeepsHeartbeatAlive(t *testing.T) {
	hub, st, srv := newSinkHub(t, nil)
	nodeID := "node-nil-sink"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := []byte(`{"probe_id":"nil-sink-probe","outcome":"REJECTED"}`)
	messageID := msgID("nil-sink-probe", "probe_result")
	messageIDHex := hex.EncodeToString(messageID[:])
	if err := sendA2CExact(ctx, conn, 1, messageID, "probe_result", payload); err != nil {
		t.Fatalf("send probe_result: %v", err)
	}

	item := waitNilProbeInboxItem(t, st, messageIDHex)
	if item.MessageID != messageIDHex || item.NodeID != nodeID ||
		item.MessageType != "probe_result" || item.SemanticPayload != string(payload) ||
		item.State != store.ControlInboxReceived {
		t.Fatalf("nil-sink inbox = %+v, want exact RECEIVED probe_result", item)
	}

	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("send heartbeat after nil-sink result: %v", err)
	}
	expectSilentSession(t, conn, ctx, 150*time.Millisecond)
}

func waitNilProbeInboxItem(t *testing.T, st *store.Store, messageID string) store.ControlInboxItem {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		item, err := st.ControlInboxItemByMessageID(messageID)
		if err == nil {
			return item
		}
		time.Sleep(10 * time.Millisecond)
	}
	item, err := st.ControlInboxItemByMessageID(messageID)
	if err != nil {
		t.Fatalf("read nil-sink inbox %q: %v", messageID, err)
	}
	return item
}
