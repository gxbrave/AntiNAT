package probe

import (
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestManagerRejectsNonIndependentProvider is Story 6 cycle-2 RED evidence:
// a local/fake provider without an independent-vantage declaration must not
// be able to produce OPEN_FROM_VANTAGE or PUBLISHED_VERIFIED truth.
func TestManagerRejectsNonIndependentProvider(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	if err := env.store.SetProbeProviderIndependentVantage("prov-1", false); err != nil {
		t.Fatal(err)
	}
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := env.store.GetProbeOperation(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == string(protocol.OutcomeNoIndependentVantage) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := env.store.GetProbeOperation(op.ID)
	t.Fatalf("non-independent provider status = %q, want %s", got.Status, protocol.OutcomeNoIndependentVantage)
}
