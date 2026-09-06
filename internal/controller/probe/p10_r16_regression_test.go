package probe

import (
	"context"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

const r16RuntimeSnapshot = `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"NOT_REQUIRED","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"UNKNOWN","publication_state":"NONE","data_plane_state":"READY"}`

func TestR16ArmRequiresCurrentRuntimeMirror(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.store.CreateNode(store.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.CreateForward(store.Forward{
		ID: "f1", NodeID: "n1", Name: "fwd", Protocol: "tcp",
		CurrentActivationID: "act-1", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := env.manager.Arm(context.Background(), "n1", "f1", "act-1", "198.51.100.7:8080")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Arm without runtime mirror = %v, want ErrNotFound", err)
	}
	if _, err := env.store.GetForwardRuntimeStatus("f1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Arm fabricated runtime mirror: %v", err)
	}
	if live, err := env.store.CountLiveProbeOperations(); err != nil || live != 0 {
		t.Fatalf("live operations after rejected Arm = %d, %v; want 0", live, err)
	}
}

func TestR16ArmRejectsStaleRuntimeMirror(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.store.CreateNode(store.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.CreateForward(store.Forward{
		ID: "f1", NodeID: "n1", Name: "fwd", Protocol: "tcp",
		CurrentActivationID: "act-old", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.store.SetForwardRuntimeStatus("f1", "act-old", 1, r16RuntimeSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := env.store.CASForwardActivation("f1", 1, "act-new"); err != nil {
		t.Fatal(err)
	}

	_, err := env.manager.Arm(context.Background(), "n1", "f1", "act-new", "198.51.100.7:8080")
	if !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("Arm with stale runtime mirror = %v, want ErrCASConflict", err)
	}
	got, err := env.store.GetForwardRuntimeStatus("f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ActivationID != "act-old" || got.SnapshotJSON != r16RuntimeSnapshot {
		t.Fatalf("stale runtime mirror mutated: %+v", got)
	}
	if live, err := env.store.CountLiveProbeOperations(); err != nil || live != 0 {
		t.Fatalf("live operations after rejected Arm = %d, %v; want 0", live, err)
	}
}
