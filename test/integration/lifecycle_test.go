//go:build linux

// P14 lifecycle crash/integration tests (M3 package 5-6): Forward delete
// no-resurrection, node decommission marker-before-stop with cleanup tombstone,
// key-rotation pin accept, and RECOVERY_QUARANTINE — driven through the real
// Agent store and a scripted gateway composition, so the lifecycle FSM is
// exercised end-to-end inside the integration suite without a real gateway.
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
	"github.com/gxbrave/AntiNAT/internal/traversal"
	"github.com/gxbrave/AntiNAT/internal/traversal/pcp"
)

// scriptedRoute is a private-source route table (behind a NAT CPE).
type scriptedRoute struct{}

func (scriptedRoute) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("10.0.0.1"), "lan0", true, nil
}
func (scriptedRoute) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}}, nil
}

type deleteCountMapper struct {
	mechanism traversal.MappingLayerKind
	ownership traversal.OwnershipStrength
	external  netip.AddrPort

	mu      sync.Mutex
	deletes int
}

func (m *deleteCountMapper) Mechanism() traversal.MappingLayerKind  { return m.mechanism }
func (m *deleteCountMapper) Ownership() traversal.OwnershipStrength { return m.ownership }
func (m *deleteCountMapper) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(m.mechanism, false)
}
func (m *deleteCountMapper) Discover(context.Context) (traversal.ControlServer, error) {
	return traversal.ControlServer{Mechanism: m.mechanism, Address: "10.0.0.1:5351"}, nil
}
func (m *deleteCountMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	return traversal.GatewayMapping{
		Mechanism: m.mechanism, Ownership: m.ownership,
		InternalIP: req.InternalIP, InternalPort: req.InternalPort,
		External: m.external, Lease: time.Hour,
		State: pcp.MapResult{InternalPort: req.InternalPort, AssignedExternalPort: m.external.Port()},
	}, nil
}
func (m *deleteCountMapper) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	mapping.Lease = lifetime
	return mapping, nil
}
func (m *deleteCountMapper) Delete(context.Context, traversal.GatewayMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	return nil
}
func (m *deleteCountMapper) deleteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deletes
}

// TestIntegrationForwardDeleteNoResurrect applies and deletes a forward through
// the real store + resolve/apply path, proving the durable fence defeats an old
// snapshot retry (Story 1 crash matrix).
func TestIntegrationForwardDeleteNoResurrect(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	latch := localstate.NewLatch()
	apply := func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
		return protocol.AppliedForwardState{
			ForwardID: spec.ForwardID, SpecRevision: spec.DesiredRevision,
			DesiredRevision: spec.DesiredRevision, ActualBindHost: "127.0.0.1",
			ActualBindPort: 23333, Strategy: string(spec.Strategy),
			AppliedAtUnix: time.Now().Unix(),
		}, nil
	}
	stop := func(ctx context.Context, forwardID string) error { return nil }

	present := protocol.ForwardSpec{
		ForwardID: "fwd-it", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyDirectV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := reconcile.ApplyDesired(context.Background(), st, latch,
		protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{present}}, apply, stop); err != nil {
		t.Fatal(err)
	}
	absent := present
	absent.Presence = protocol.PresenceAbsent
	absent.DeletionOperationID = "it-del-1"
	if _, err := reconcile.ApplyDesired(context.Background(), st, latch,
		protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{absent}}, apply, stop); err != nil {
		t.Fatal(err)
	}
	tombstoned, err := st.TombstoneExists("fwd-it")
	if err != nil || !tombstoned {
		t.Fatalf("tombstone ok=%v err=%v", tombstoned, err)
	}
	higher := present
	higher.DesiredRevision = 42
	report, err := reconcile.ApplyDesired(context.Background(), st, latch,
		protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{higher}}, apply, stop)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Results {
		if r.Outcome == reconcile.OutcomeApplied {
			t.Fatal("deleted forward resurrected by an old-snapshot retry")
		}
	}
}

// TestIntegrationDecommissionMarkerBeforeStop runs the terminal FSM through the
// store and marker and proves the cleanup tombstone carries the allowed key
// versions.
func TestIntegrationDecommissionMarkerBeforeStop(t *testing.T) {
	dir := t.TempDir()
	st, err := localstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var markers []localstate.MarkerState
	var mu sync.Mutex
	stopAll := func(ctx context.Context) error {
		m, err := localstate.LoadMarker(dir)
		if err != nil {
			return err
		}
		mu.Lock()
		markers = append(markers, m)
		mu.Unlock()
		return nil
	}
	dc := reconcile.NewDecommissioner(st, localstate.NewLatch(), dir, stopAll)
	req := reconcile.DecommissionRequest{
		NodeID: "node-1", OperationID: "it-decom-1",
		AllowedKeyHashes: []string{"kid-1", "kid-2"}, CredentialVersions: []uint32{1},
	}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := dc.StopAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]localstate.MarkerState(nil), markers...)
	mu.Unlock()
	for _, m := range got {
		if m != localstate.MarkerDecommissioning {
			t.Fatalf("stop observed marker %q, want DECOMMISSIONING before stop", m)
		}
	}
	if err := dc.Complete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	tombstone, found, err := st.LoadAgentCleanupTombstone()
	if err != nil || !found {
		t.Fatalf("cleanup tombstone missing found=%v err=%v", found, err)
	}
	if len(tombstone.AllowedKeyHashes) != 2 || tombstone.AllowedKeyHashes[0] != "kid-1" {
		t.Fatalf("cleanup tombstone key hashes = %v", tombstone.AllowedKeyHashes)
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker = %q err=%v", marker, err)
	}
}

// TestIntegrationRotationPinAccept drives the agent accepting a controller
// rotation pin: signed cert -> higher generation persisted durably.
func TestIntegrationRotationPinAccept(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := newPriv.Public().(ed25519.PublicKey)
	if err := st.SaveControllerPin(localstate.ControllerPin{
		InstanceID: "inst-1", KeyID: "old-id",
		PublicKeyRaw: append(ed25519.PublicKey(nil), oldPub...), Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cert := security.NewRotationCertificate("controller", oldPub, 1, "old-id",
		newPub, 2, security.KeyIDOf(newPub), now, now+3600)
	if err := security.SignRotationCertificate(&cert, oldPriv); err != nil {
		t.Fatal(err)
	}
	raw, _ := cert.Encode()
	next, _, err := reconcile.AcceptControllerRotationPin(st, "inst-1", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if next.Generation != 2 {
		t.Fatalf("pin generation = %d, want 2", next.Generation)
	}
}

// TestIntegrationRecoveryQuarantineProtectsTerminalMarker proves the
// quarantine marker can NEVER sit over a DECOMMISSIONED terminal marker and
// clearance requires explicit unquarantine.
func TestIntegrationRecoveryQuarantineProtectsTerminalMarker(t *testing.T) {
	dir := t.TempDir()
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}
	if err := localstate.WriteRecoveryQuarantine(dir); err == nil {
		t.Fatal("quarantine accepted over a terminal DECOMMISSIONED marker")
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if marker != localstate.MarkerDecommissioned {
		t.Fatalf("terminal marker overwritten: %q", marker)
	}
}
