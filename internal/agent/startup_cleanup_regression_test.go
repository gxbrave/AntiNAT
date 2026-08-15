package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

type startupWaitClient struct {
	waited atomic.Bool
}

func (c *startupWaitClient) Connect(context.Context) error                     { return nil }
func (c *startupWaitClient) SendMessage(context.Context, string, []byte) error { return nil }
func (c *startupWaitClient) Shutdown()                                         {}
func (c *startupWaitClient) Wait()                                             { c.waited.Store(true) }

// TestStartRecoveryFailureWaitsForControlSession ensures every startup error
// path joins the control client before closing the localstate store. The fake
// client makes the lifecycle fence observable without relying on goroutine
// scheduling or a remote WebSocket's close timing.
func TestStartRecoveryFailureWaitsForControlSession(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	desired := protocol.DesiredState{NodeID: "node-startup", Forwards: []protocol.ForwardSpec{{
		ForwardID: "fwd-recovery", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:1",
		Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1,
	}}}
	applied := protocol.AppliedForwardState{
		ForwardID: "fwd-recovery", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "127.0.0.1", ActualBindPort: 40001,
		Strategy: "direct-v4", LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(desired, []localstate.ForwardApply{{
		ForwardID: "fwd-recovery", Outcome: localstate.ApplyApplied, Applied: &applied,
	}}); err != nil {
		st.Close()
		t.Fatal(err)
	}

	mgr := reconcile.NewProbeManager(reconcile.ProbeManagerOptions{Store: st, Clock: time.Now})
	routes := &mutableRouteTable{iface: "eth0", hasDefault: false}
	d := newDataPlane(dataPlaneConfig{Store: st, ProbeMgr: mgr, RouteTable: routes, Clock: time.Now})
	client := &startupWaitClient{}
	a := &App{
		cfg:         Config{LivenessInterval: time.Second, RouteTable: routes},
		store:       st,
		client:      client,
		probeMgr:    mgr,
		dp:          d,
		activations: make(map[string]*reconcile.Activation),
	}

	err = a.Start(context.Background())
	if err == nil {
		t.Fatal("Start unexpectedly succeeded without a direct-v4 route")
	}
	if !client.waited.Load() {
		t.Fatal("startup recovery failure did not wait for the control client")
	}
}
