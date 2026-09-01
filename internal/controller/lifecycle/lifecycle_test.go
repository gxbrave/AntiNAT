// P14 Story 3: force delete / cleanup-only. The cleanup tombstone carries the
// allowed key versions; the old key can never receive desired or secrets
// (enqueue guard), and the never-reconnect state stays unconfirmed until the
// bounded decommission ACK arrives. Also covers the restricted session gate.
package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustNode(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if err := s.CreateNode(store.Node{ID: id, Name: id}); err != nil {
		t.Fatal(err)
	}
}

// TestForceDeleteCreatesTombstoneAndConfirmsLazily verifies the live/force
// lifecycle: tombstone persists (force, remote_cleanup_confirmed=false), a
// decommission command may still be enqueued, and the bounded ACK later marks
// the node confirmed.
func TestForceDeleteCreatesTombstoneAndConfirmsLazily(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	mustNode(t, s, "node-forcing")

	enqueued := 0
	enqueue := func(item store.ControlOutboxItem) error {
		if item.MessageType != "node_decommission" {
			t.Fatalf("force delete must only enqueue node_decommission, got %q", item.MessageType)
		}
		if err := s.EnqueueControlOutbox(item); err != nil {
			return err
		}
		enqueued++
		return nil
	}
	res, err := ForceDeleteNode(ctx, s, DecommissionRequest{
		NodeID: "node-forcing", OperationID: "decom-f-1", Force: true,
		AllowedKeyHashes: []string{"old-key-1"},
	}, enqueue)
	if err != nil {
		t.Fatalf("force delete: %v", err)
	}
	if res.RemoteCleanupConfirmed {
		t.Fatal("force delete must start with remote_cleanup_confirmed=false")
	}
	ts, err := s.NodeCleanupTombstone("node-forcing")
	if err != nil {
		t.Fatal(err)
	}
	if !ts.Force || ts.RemoteCleanupConfirmed {
		t.Fatalf("tombstone force/confirmed = %v/%v", ts.Force, ts.RemoteCleanupConfirmed)
	}
	if len(ts.AllowedKeyHashes) != 1 || ts.AllowedKeyHashes[0] != "old-key-1" {
		t.Fatalf("tombstone key hashes = %v", ts.AllowedKeyHashes)
	}
	if enqueued != 1 {
		t.Fatalf("enqueued = %d, want 1", enqueued)
	}
	if err := ConfirmRemoteCleanup(ctx, s, "node-forcing"); err != nil {
		t.Fatal(err)
	}
	ts2, _ := s.NodeCleanupTombstone("node-forcing")
	if !ts2.RemoteCleanupConfirmed {
		t.Fatal("remote cleanup confirmation did not persist")
	}
}

// TestCleanupOnlyRefusesDesiredAndSecrets is the story's core RED: once the
// tombstone exists, the old key can never receive desired/secrets/rotation,
// but a cleanup-authorized type still flows.
func TestCleanupOnlyRefusesDesiredAndSecrets(t *testing.T) {
	s := openStore(t)
	mustNode(t, s, "node-old")
	ctx := context.Background()

	if err := s.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-old", OperationID: "decom-f-2", Force: true,
		AllowedKeyHashes: []string{"old-key-1"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"desired", "forward_delete", "probe_arm", "key_rotation_prepare", "key_rotation_commit", "restore_reconcile"} {
		err := s.EnqueueControlOutbox(store.ControlOutboxItem{
			OperationID: "op-" + forbidden, MessageType: forbidden, NodeID: "node-old",
			SemanticPayload: `{}`,
		})
		if err == nil {
			t.Fatalf("EnqueueControlOutbox(%q) succeeded on a cleanup-only node", forbidden)
		}
	}
	// The decommission retry channel stays open.
	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "decom-f-2", MessageType: "node_decommission", NodeID: "node-old",
		SemanticPayload: `{}`,
	}); err != nil {
		t.Fatalf("cleanup-authorized enqueue refused: %v", err)
	}
	cleanupOnly, err := s.IsCleanupOnly("node-old")
	if err != nil || !cleanupOnly {
		t.Fatalf("IsCleanupOnly = %v err=%v", cleanupOnly, err)
	}
	_ = ctx
}

// TestCleanupOnlyInboundSessionGate verifies the restricted session boundary:
// only the terminal ACK / heartbeat / status / operation frames are accepted.
func TestCleanupOnlyInboundSessionGate(t *testing.T) {
	for _, allowed := range []string{"node_decommission_ack", "heartbeat", "status", "message_receipt", "operation_complete"} {
		if !AllowedInboundCleanupOnly(allowed) {
			t.Fatalf("%q should be allowed on a cleanup-only session", allowed)
		}
	}
	for _, forbidden := range []string{"desired_result", "forward_delete_ack", "probe_armed", "probe_result"} {
		if AllowedInboundCleanupOnly(forbidden) {
			t.Fatalf("%q must be forbidden on a cleanup-only session", forbidden)
		}
	}
}

// TestFinalizeRestoreResumesDispatch (repair-1 H2a): with no caller for
// store.AdvanceRestorePhase the controller stayed in RESTORE_RECONCILIATION
// forever and refused automatic dispatch indefinitely. FinalizeRestore advances
// the durable restore op to AUTHORIZED; per-node ReauthorizeNode clears the node
// quarantine, after which a forbidden orchestrating enqueue is allowed again.
func TestFinalizeRestoreResumesDispatch(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	mustNode(t, s, "node-reauth")

	op := store.RestoreOperation{ID: "rest-final-1", ControllerInstance: "ci-1", ManifestSHA256: "abc", SchemaVersion: 1}
	if err := s.EnterRestoreReconciliation(op); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "blk-1", MessageType: "desired", NodeID: "node-reauth", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("desired enqueued during RESTORE_RECONCILIATION")
	}

	completed, err := FinalizeRestore(ctx, s, "rest-final-1")
	if err != nil {
		t.Fatalf("FinalizeRestore: %v", err)
	}
	if completed.Phase != "AUTHORIZED" {
		t.Fatalf("finalized phase = %q, want AUTHORIZED", completed.Phase)
	}
	reconciling, err := s.IsRestoreReconciling()
	if err != nil || reconciling {
		t.Fatalf("IsRestoreReconciling = %v err=%v after finalize", reconciling, err)
	}
	// Global gate open but per-node quarantine still set.
	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "blk-2", MessageType: "desired", NodeID: "node-reauth", SemanticPayload: `{}`,
	}); err == nil {
		t.Fatal("desired enqueued for a still-quarantined node after global finalize")
	}
	if err := ReauthorizeNode(ctx, s, "node-reauth"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "ok-1", MessageType: "desired", NodeID: "node-reauth", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatalf("desired enqueue refused after finalize + node reauthorization: %v", err)
	}
}

// TestForceDeleteTerminatesOnlineSession (repair-1 M3a): the optional
// terminateSession callback fires with the node id after the durable tombstone
// is written, so an established session cannot outlive the tombstone.
func TestForceDeleteTerminatesOnlineSession(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	mustNode(t, s, "node-day")

	var terminated []string
	var mu sync.Mutex
	terminatedCount := 0
	res, err := ForceDeleteNode(ctx, s, DecommissionRequest{
		NodeID: "node-day", OperationID: "decom-day", Force: true,
	}, nil, func(nodeID string) error {
		mu.Lock()
		terminated = append(terminated, nodeID)
		terminatedCount++
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("force delete: %v", err)
	}
	_ = res
	if terminatedCount != 1 || len(terminated) == 0 || terminated[0] != "node-day" {
		t.Fatalf("terminate callbacks = %v count=%d, want [node-day]/1", terminated, terminatedCount)
	}
	ts, err := s.NodeCleanupTombstone("node-day")
	if err != nil {
		t.Fatalf("tombstone missing after force delete with termination: %v", err)
	}
	if !ts.Force {
		t.Fatalf("tombstone force = %v", ts.Force)
	}
}

// TestForceDeleteMissingNode fails closed.
func TestForceDeleteMissingNode(t *testing.T) {
	s := openStore(t)
	_, err := ForceDeleteNode(context.Background(), s, DecommissionRequest{
		NodeID: "no-such-node", OperationID: "decom-f-3",
	}, nil)
	if err == nil {
		t.Fatal("force delete of a missing node must fail")
	}
	if !errors.Is(err, store.ErrNodeNotFound) {
		t.Fatalf("force delete error = %v, want ErrNodeNotFound", err)
	}
}
