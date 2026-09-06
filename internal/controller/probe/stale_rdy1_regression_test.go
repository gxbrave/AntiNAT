package probe

import (
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// A valid signed RDY1 delivered after the forward has rotated must not launch
// a provider request or admit stale evidence. The operation is terminalized
// with the generic probe rejection outcome under the current forward fence.
func TestHandleArmedRejectsStaleForwardRevisionAndActivation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		currentActive string
	}{
		{name: "activation", currentActive: "act-new"},
		// CASForwardActivation intentionally retains the same activation while
		// advancing the parent revision. Activation identity alone is therefore
		// insufficient to admit delayed RDY1 delivery.
		{name: "revision", currentActive: "act-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, false)
			env.createNodeForward(t)
			op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
			if err := env.store.CASForwardActivation("f1", 1, tc.currentActive); err != nil {
				t.Fatal(err)
			}
			if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
				t.Fatalf("stale RDY1: %v", err)
			}
			got, err := env.store.GetProbeOperation(op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != string(protocol.OutcomeRejected) {
				t.Fatalf("stale RDY1 status = %q, want REJECTED", got.Status)
			}
			if got := env.provider.requestTotal(); got != 0 {
				t.Fatalf("stale RDY1 launched %d provider requests", got)
			}
		})
	}
}

func TestHandleArmedRejectsMissingExpectedRevision(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	rawDB := openR16QRawDB(t, env)
	if _, err := rawDB.Exec(`UPDATE probe_operations SET expected_forward_revision = 0 WHERE id = ?`, op.ID); err != nil {
		t.Fatalf("clear expected forward revision: %v", err)
	}
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatalf("missing-revision RDY1: %v", err)
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("missing-revision RDY1 status = %q, want REJECTED", got.Status)
	}
	if got := env.provider.requestTotal(); got != 0 {
		t.Fatalf("missing-revision RDY1 launched %d provider requests", got)
	}
}
