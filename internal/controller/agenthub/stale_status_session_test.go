package agenthub_test

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// TestStaleActivationStatusDoesNotKillLiveSession proves that a valid status
// for an old activation is consumed as harmless stale state. The same
// authenticated WebSocket must remain usable for heartbeat and later traffic.
func TestStaleActivationStatusDoesNotKillLiveSession(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "node-stale-stat"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateForward(store.Forward{
		ID: "stale-status-forward", NodeID: nodeID, Name: "stale-status-forward",
		Protocol: "tcp", CurrentActivationID: "current-activation", Revision: 2,
	}); err != nil {
		t.Fatal(err)
	}

	var hub *agenthub.Hub
	mgr, err := probe.NewManager(probe.ManagerConfig{
		Store: st, Keyring: kr, Clock: time.Now,
		NodePublicKey: func(id string) (ed25519.PublicKey, bool) {
			if hub == nil || id != nodeID {
				return nil, false
			}
			return hub.AgentPublicKey(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hub, err = agenthub.NewHub(agenthub.Config{
		Store: st, Keyring: kr,
		Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock:      time.Now, ProbeSink: mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)

	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv.URL, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stalePayload := []byte(`{"forward_id":"stale-status-forward","activation":"old-activation","generation":1,"snapshot":{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"HEALTHY","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"UNKNOWN","publication_state":"NONE","data_plane_state":"READY"}}`)
	if err := sendA2CExact(ctx, conn, 1, msgID("stale-status", "status"), "status", stalePayload); err != nil {
		t.Fatalf("send stale status: %v", err)
	}
	if err := conn.sendA2C(ctx, 2, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("heartbeat after stale status: %v", err)
	}
	// A second valid status after the heartbeat is the observable liveness
	// proof: a fatal dispatch would have ended frameLoop before this call.
	if err := sendA2CExact(ctx, conn, 3, msgID("stale-status-followup", "status"), "status", stalePayload); err != nil {
		t.Fatalf("follow-up status after heartbeat: %v", err)
	}

	// Confirm the stale status was classified and audited by the production
	// manager/hub path rather than merely accepted by a test sink.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events, eventErr := st.AdminEventsAfter(0, 100)
		if eventErr == nil {
			count := 0
			for _, event := range events {
				if event.EventType == "CONTROL_STATUS_STALE" {
					count++
				}
			}
			if count >= 2 {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	events, err := st.AdminEventsAfter(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.EventType == "CONTROL_STATUS_STALE" {
			count++
		}
	}
	t.Fatalf("CONTROL_STATUS_STALE events = %d, want 2; events = %+v", count, events)
}
