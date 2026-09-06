package probe

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func createManagerCleanupOperation(t *testing.T, env *testEnv, id string, expiresAt int64) {
	t.Helper()
	if _, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID: id, NodeID: "n1", ForwardID: "f1", ActivationID: "act-1", ProviderID: "prov-1",
		Status: "PENDING", Endpoint: "198.51.100.7:8080", ArmHex: "41524d31", TTLMS: 30_000,
		ExpiryOpaque: "00112233445566778899aabbccddeeff", ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("create cleanup operation %s: %v", id, err)
	}
}

// one manager sweep must use its configured batch size. An expired
// operation backlog is reclaimed in bounded passes instead of one unbounded
// status transition transaction.
func TestManagerSweepExpiryIsBounded(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	base := time.Now().Truncate(time.Second)
	for i := 0; i < 4; i++ {
		createManagerCleanupOperation(t, env, "old-op-"+string(rune('0'+i)), base.Unix()-1)
	}

	mgr, err := NewManager(ManagerConfig{
		Store:               env.store,
		Keyring:             env.keyring,
		Clock:               func() time.Time { return base },
		NodePublicKey:       func(string) (ed25519.PublicKey, bool) { return env.nodePub, true },
		CleanupBatchSize:    2,
		ResultRetention:     time.Hour,
		SweepInterval:       time.Hour,
		MaxActiveOperations: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.sweepOnce(base); err != nil {
		t.Fatal(err)
	}
	timedOut, err := env.store.ListProbeOperationsByStatus("TIMEOUT")
	if err != nil {
		t.Fatal(err)
	}
	if len(timedOut) != 2 {
		t.Fatalf("first sweep timed out %d operations, want 2", len(timedOut))
	}
	if err := mgr.sweepOnce(base); err != nil {
		t.Fatal(err)
	}
	timedOut, err = env.store.ListProbeOperationsByStatus("TIMEOUT")
	if err != nil {
		t.Fatal(err)
	}
	if len(timedOut) != 4 {
		t.Fatalf("second sweep timed out %d operations, want 4", len(timedOut))
	}
}

// admission uses the same controlled clock as durable operation creation,
// so an active row created at a fixed timestamp still counts against the cap.
func TestManagerArmUsesBoundedActiveState(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	base := time.Unix(100_000, 0)
	mgr, err := NewManager(ManagerConfig{
		Store:               env.store,
		Keyring:             env.keyring,
		Clock:               func() time.Time { return base },
		MaxActiveOperations: 1,
		NodePublicKey:       func(string) (ed25519.PublicKey, bool) { return env.nodePub, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Arm(context.Background(), "n1", "f1", "act-1", "198.51.100.7:8080"); err != nil {
		t.Fatalf("first arm: %v", err)
	}
	if _, err := mgr.Arm(context.Background(), "n1", "f1", "act-1", "198.51.100.7:8080"); err == nil {
		t.Fatal("second live arm bypassed active operation bound")
	}
}

// manager shutdown must join the context-owned sweeper without waiting
// for its next wall-clock tick.
func TestManagerCloseCancelsSweeperPromptly(t *testing.T) {
	env := newTestEnv(t, false)
	mgr, err := NewManager(ManagerConfig{
		Store:            env.store,
		Keyring:          env.keyring,
		NodePublicKey:    func(string) (ed25519.PublicKey, bool) { return env.nodePub, true },
		SweepInterval:    time.Hour,
		CleanupBatchSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		_ = mgr.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("manager Close did not join the cancelled sweeper")
	}
}
