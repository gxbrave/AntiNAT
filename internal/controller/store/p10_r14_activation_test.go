package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

const r14FirstHopRuntimeSnapshot = `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"FIRST_HOP_MAPPED","keepalive_state":"HEALTHY","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"PASS","publication_state":"NONE","data_plane_state":"READY"}`

// R14 RED: PublishProbeJoin must validate the final merged snapshot, not only
// the probe-owned fields supplied by the caller. A prior FIRST_HOP_MAPPED
// mapping must never be combined with verified publication evidence.
func TestR14PublishProbeJoinRejectsInvalidMergedActivationSnapshot(t *testing.T) {
	fixture := newAuthenticatedJoinFixture(t)
	if err := fixture.store.SetForwardRuntimeStatus(fixture.forwardID, fixture.activationID, 1, r14FirstHopRuntimeSnapshot); err != nil {
		t.Fatalf("seed first-hop runtime snapshot: %v", err)
	}

	nodePriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	err := fixture.store.PublishProbeJoin(
		fixture.operationID,
		"IN_FLIGHT",
		fixture.forwardID,
		fixture.activationID,
		authenticatedJoinSnapshot,
		nodePriv.Public().(ed25519.PublicKey),
	)
	if err == nil {
		t.Fatal("invalid merged FIRST_HOP_MAPPED/PUBLISHED_VERIFIED snapshot was committed")
	}
	if !errors.Is(err, ErrProbeJoinIncomplete) {
		t.Fatalf("invalid merged snapshot error = %v, want ErrProbeJoinIncomplete", err)
	}

	op, err := fixture.store.GetProbeOperation(fixture.operationID)
	if err != nil {
		t.Fatalf("read probe operation after rejected merge: %v", err)
	}
	if op.Status != "IN_FLIGHT" {
		t.Fatalf("rejected merged snapshot changed operation status to %q", op.Status)
	}
	status, err := fixture.store.GetForwardRuntimeStatus(fixture.forwardID)
	if err != nil {
		t.Fatalf("read runtime status after rejected merge: %v", err)
	}
	if status.SnapshotJSON != r14FirstHopRuntimeSnapshot {
		t.Fatalf("rejected merged snapshot mutated runtime mirror: %s", status.SnapshotJSON)
	}
}
