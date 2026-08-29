package probe

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

type gatedRoundTripper struct {
	mu       sync.Mutex
	requests int
	first    chan struct{}
	release  chan struct{}
}

func (t *gatedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests++
	requestNumber := t.requests
	if requestNumber == 1 {
		close(t.first)
	}
	t.mu.Unlock()
	if requestNumber == 1 {
		<-t.release
	}
	return &http.Response{
		StatusCode:    http.StatusInternalServerError,
		Status:        "500 Internal Server Error",
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
		Request:       req,
	}, nil
}

func (t *gatedRoundTripper) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.requests
}

func waitProviderRoundAvailable(t *testing.T, manager *Manager, operationID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		_, active := manager.active[operationID]
		available := len(manager.rounds) == 0
		manager.mu.Unlock()
		if !active && available {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("provider round %q did not release its slot", operationID)
}

func parseProbeArmPayload(payload string) (protocol.ProbeArm, error) {
	return protocol.ParseProbeArm([]byte(payload))
}

func waitForProviderStatus(t *testing.T, st *store.Store, operationID, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		op, err := st.GetProbeOperation(operationID)
		if err == nil && op.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	op, err := st.GetProbeOperation(operationID)
	if err != nil {
		t.Fatalf("read provider operation %q: %v", operationID, err)
	}
	t.Fatalf("provider operation %q status = %q, want %q", operationID, op.Status, want)
}

// TestProviderCapacityKeepsArmedOperationRetryable proves temporary provider
// admission pressure is not provider evidence. A valid second RDY1 remains
// ARMED while the only provider slot is occupied, then recovery starts exactly
// one request after the first round releases its slot.
func TestProviderCapacityKeepsArmedOperationRetryable(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	if err := env.store.CreateNode(store.Node{ID: "n2", Name: "n2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.CreateForward(store.Forward{
		ID: "f2", NodeID: "n2", Name: "f2", Protocol: "tcp",
		CurrentActivationID: "act-2", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.store.SetForwardRuntimeStatus("f2", "act-2", 1, r16RuntimeSnapshot); err != nil {
		t.Fatal(err)
	}

	transport := &gatedRoundTripper{first: make(chan struct{}), release: make(chan struct{})}
	env.manager.rounds = make(chan struct{}, 1)
	env.manager.client.Transport = transport

	opA, armA := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, armA)); err != nil {
		t.Fatalf("admit first probe_armed: %v", err)
	}
	select {
	case <-transport.first:
	case <-time.After(3 * time.Second):
		t.Fatal("first provider request did not occupy the provider slot")
	}

	opB, err := env.manager.Arm(context.Background(), "n2", "f2", "act-2", "198.51.100.8:8080")
	if err != nil {
		t.Fatalf("arm second operation: %v", err)
	}
	item, err := env.store.ControlOutboxItemByOperation(opB.ID, "probe_arm")
	if err != nil {
		t.Fatal(err)
	}
	armB, err := parseProbeArmPayload(item.SemanticPayload)
	if err != nil {
		t.Fatalf("parse second ARM1: %v", err)
	}
	if err := env.manager.HandleProbeMessage("n2", "probe_armed", signRDY1(t, env.nodePriv, armB)); err == nil {
		t.Fatal("capacity-saturated probe_armed unexpectedly succeeded")
	}
	gotB, err := env.store.GetProbeOperation(opB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotB.Status != "ARMED" {
		t.Fatalf("capacity-saturated operation status = %q, want ARMED", gotB.Status)
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("provider requests while slot is occupied = %d, want 1", got)
	}

	close(transport.release)
	waitProviderRoundAvailable(t, env.manager, opA.ID)
	waitForProviderStatus(t, env.store, opA.ID, "PROBE_INFRA_UNAVAILABLE")

	if err := env.manager.recoverOperations(); err != nil {
		// Recovery reports the second simulated provider HTTP failure through its
		// background error path; the admission itself must still have occurred.
		if got := transport.count(); got < 2 {
			t.Fatalf("recovery returned before retry admission: %v", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && transport.count() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("provider requests after releasing capacity = %d, want exactly 2", got)
	}
	if err := env.manager.recoverOperations(); err != nil {
		t.Logf("second recovery reported expected simulated provider failure: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := transport.count(); got != 2 {
		t.Fatalf("recovery launched duplicate provider request = %d, want 2", got)
	}
}
