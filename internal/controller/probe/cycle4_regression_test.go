package probe

import (
	"context"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// The arm must be bound to the forward's current activation before a probe
// operation or probe_arm outbox row is created. Deferring this check until
// OPEN publication leaves stale work that can race a newer activation.
func TestArmRejectsStaleForwardActivation(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.store.CreateNode(store.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.CreateForward(store.Forward{
		ID: "f-current", NodeID: "n1", Name: "current", Protocol: "tcp",
		CurrentActivationID: "act-current", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := env.manager.Arm(context.Background(), "n1", "f-current", "act-stale", "198.51.100.7:8080"); err == nil {
		t.Fatal("arm accepted an activation that is stale for the forward")
	}
	live, err := env.store.CountLiveProbeOperations()
	if err != nil {
		t.Fatalf("count live operations: %v", err)
	}
	if live != 0 {
		t.Fatalf("stale activation left %d live probe operations", live)
	}
}

// A provider result must not be able to install an empty or malformed
// challenge into the durable operation row. The challenge is later the join
// binding for WAN1, ACK1, and RCT1, so accepting it here makes the journal
// ambiguous even when publication eventually rejects the operation.
func TestSetProbeOperationChallengeRejectsMalformedHash(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, _ := env.armAndGetPayload(t, "198.51.100.7:8080")

	if err := env.store.SetProbeOperationChallenge(op.ID, "not-a-sha256-hash"); err == nil {
		t.Fatal("malformed challenge hash was persisted")
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.ChallengeHash != "" {
		t.Fatalf("malformed challenge persisted as %q", got.ChallengeHash)
	}
}

// Reconnecting agents resend the same deterministic RCT1 receipt until the
// Controller's semantic acknowledgement arrives. An exact duplicate of an
// already-journaled artifact is idempotent and must not turn a live operation
// into REJECTED merely because the first delivery raced the acknowledgement.
func TestDuplicateProbeReceiptIsIdempotent(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("set operation armed: %v", err)
	}
	receipt := signRCT1(t, env.nodePriv, arm, [32]byte{1})
	if err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", receipt); err != nil {
		t.Fatalf("first receipt: %v", err)
	}
	if err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", receipt); err != nil {
		t.Fatalf("duplicate receipt: %v", err)
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != "ARMED" {
		t.Fatalf("duplicate receipt changed live operation to %q", got.Status)
	}
}
