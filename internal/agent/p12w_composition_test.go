// P12W Stories 2/3 composition tests: the composed data plane acquires a TCP
// explicit-gateway forward through the traversal.Manager, the acquisition
// carries the durable journal reference, the mechanism's honest ownership and
// a same-tuple STUN layer, and hot updates preserve the SAME acquisition while
// a strategy change fails closed.
package agent

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// p12wRouteTable is a scripted private-source route table (the normal shape
// behind a NAT CPE).
type p12wRouteTable struct{}

func (p12wRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("10.0.0.1"), "lan0", true, nil
}

func (p12wRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}}, nil
}

// p12wMapper is a scripted PCP gateway mapper.
type p12wMapper struct {
	mechanism traversal.MappingLayerKind
	ownership traversal.OwnershipStrength
	control   traversal.ControlServer
	external  netip.AddrPort
	lease     time.Duration

	mu      sync.Mutex
	deletes int
}

func (m *p12wMapper) Mechanism() traversal.MappingLayerKind  { return m.mechanism }
func (m *p12wMapper) Ownership() traversal.OwnershipStrength { return m.ownership }
func (m *p12wMapper) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(m.mechanism, false)
}
func (m *p12wMapper) Discover(context.Context) (traversal.ControlServer, error) {
	return m.control, nil
}
func (m *p12wMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	return traversal.GatewayMapping{
		Mechanism:    m.mechanism,
		Ownership:    m.ownership,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     m.external,
		Lease:        m.lease,
		State:        "fake-state",
	}, nil
}
func (m *p12wMapper) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	mapping.Lease = lifetime
	return mapping, nil
}
func (m *p12wMapper) Delete(context.Context, traversal.GatewayMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	return nil
}

func (m *p12wMapper) deleteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deletes
}

// p12wListenerSource is a scripted ListenerSource that reports the requested
// tuple but binds a real loopback listener so no private source address must
// exist on the test host.
type p12wListenerSource struct {
	mu       sync.Mutex
	acquired []traversal.TupleKey
	released int
}

func (s *p12wListenerSource) Acquire(ctx context.Context, owner string, key traversal.TupleKey) (net.Listener, traversal.TupleKey, traversal.ReleaseFunc, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, traversal.TupleKey{}, nil, err
	}
	actual := key
	actual.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	s.mu.Lock()
	s.acquired = append(s.acquired, actual)
	s.mu.Unlock()
	return listener, actual, func() error {
		s.mu.Lock()
		s.released++
		s.mu.Unlock()
		return listener.Close()
	}, nil
}

// p12wObserver is a scripted same-tuple STUN observer returning a fixed
// endpoint without dialing.
type p12wObserver struct {
	mu     sync.Mutex
	result netip.AddrPort
	reqs   int
}

func (o *p12wObserver) observe(ctx context.Context, req traversal.StunObserveRequest) (netip.AddrPort, error) {
	o.mu.Lock()
	o.reqs++
	o.mu.Unlock()
	return o.result, nil
}

func (o *p12wObserver) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reqs
}

// p12wGatewayComposition builds a data plane wired exactly like the composed
// app for gateway routes: the shared-port gateway manager + the same manager
// observer + a cached detection profile resolving explicit-gateway to PCP.
func p12wGatewayComposition(t *testing.T) (*dataPlane, *p12wMapper, *p12wObserver, *traversal.MemoryJournal) {
	t.Helper()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mapper := &p12wMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
		lease:     time.Hour,
	}
	obs := &p12wObserver{result: netip.MustParseAddrPort("100.64.0.2:51234")}
	journal := traversal.NewMemoryJournal()
	listeners := &p12wListenerSource{}
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable:  p12wRouteTable{},
		Listeners:   listeners,
		Mappers:     map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: mapper},
		Journal:     journal,
		StunObserve: obs.observe,
	})
	profiles := newProfileStore(t.TempDir())
	if err := profiles.Save(traversal.Profile{
		Fingerprint:     "fp-lab",
		Protocol:        traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway,
		ComputedAtUnix:  time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	d := newDataPlane(dataPlaneConfig{
		Store:          st,
		RouteTable:     p12wRouteTable{},
		Clock:          time.Now,
		GatewayManager: manager,
		Journal:        journal,
		StunServers:    []string{"stun+tcp://100.64.0.1:3478"},
		ProfileStore:   profiles,
		StunObserver:   obs.observe,
		StunSource:     &p12wListenerSource{},
	})
	// The gateway route resolves its own (private) source inside the manager;
	// the data plane's direct-v4 readiness gate is not the gateway gate.
	d.capabilityReady = true
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })
	return d, mapper, obs, journal
}

// Story 2 RED: a non-nil Manager on the data plane applies a TCP
// explicit-gateway forward. The acquisition carries a journal reference, a
// Mapping with the mechanism's Ownership and a same-tuple STUN layer when a
// STUN server is configured. (Before GREEN, apply rejected every non-direct
// strategy and dataPlaneConfig had no Manager field.)
func TestDataPlaneAppliesExplicitGatewayThroughManager(t *testing.T) {
	d, mapper, obs, journal := p12wGatewayComposition(t)

	spec := protocol.ForwardSpec{
		ForwardID:       "fwd-gateway",
		Name:            "gateway",
		Protocol:        protocol.ProtocolTCP,
		Target:          "127.0.0.1:9",
		Strategy:        protocol.StrategyExplicitGateway,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	applied, err := d.apply(context.Background(), spec)
	if err != nil {
		t.Fatalf("apply explicit-gateway: %v", err)
	}
	if applied.ForwardID != spec.ForwardID || applied.Strategy != "explicit-gateway" {
		t.Fatalf("applied = %+v", applied)
	}

	d.mu.Lock()
	actor := d.forwards[spec.ForwardID]
	d.mu.Unlock()
	if actor == nil {
		t.Fatal("no actor for the gateway forward")
	}
	if actor.acq == nil {
		t.Fatal("gateway actor must expose its acquisition")
	}
	if actor.acq.JournalID == "" {
		t.Fatal("acquisition must reference its journal record")
	}
	if _, ok, err := journal.Get(actor.acq.JournalID); err != nil || !ok {
		t.Fatalf("journal record for %q ok=%v err=%v", actor.acq.JournalID, ok, err)
	}
	mapping := actor.acq.CurrentMapping()
	if mapping == nil {
		t.Fatal("acquisition must carry a live gateway mapping")
	}
	if mapping.Ownership != traversal.OwnershipStrong {
		t.Fatalf("mapping ownership = %q, want STRONG_PROTOCOL_OWNERSHIP", mapping.Ownership)
	}
	if mapping.Mechanism != traversal.LayerPCP {
		t.Fatalf("mapping mechanism = %q, want pcp", mapping.Mechanism)
	}
	if len(actor.acq.Layers) != 2 {
		t.Fatalf("layers = %+v, want gateway + same-tuple STUN", actor.acq.Layers)
	}
	stunLayer := actor.acq.Layers[1]
	if stunLayer.Kind != traversal.LayerKindSTUN || stunLayer.ParentLayer != 0 {
		t.Fatalf("stun layer = %+v, want a child of the gateway layer", stunLayer)
	}
	if stunLayer.AssignedEndpoint != obs.result.String() {
		t.Fatalf("stun endpoint = %s, want the observed endpoint", stunLayer.AssignedEndpoint)
	}
	// The gateway manager's STUN seam received the forward's own tuple.
	if actor.acq.Layers[1].InternalEndpoint != netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), actor.acq.Bind.Port).String() {
		t.Fatalf("stun internal endpoint = %s", actor.acq.Layers[1].InternalEndpoint)
	}
	if mapper.deleteCount() != 0 {
		t.Fatalf("unexpected delete before release: %d", mapper.deleteCount())
	}
}

// Story 2 (regression): a direct-v4 TCP forward still follows the
// byte-identical inline PortRegistry path when no Manager is wired.
func TestDataPlaneDirectStillWorksWithoutManager(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })

	d := newDataPlane(dataPlaneConfig{Clock: time.Now})
	spec := protocol.ForwardSpec{
		ForwardID: "direct-plain", Protocol: protocol.ProtocolTCP, Target: target.Addr().String(),
		Strategy: protocol.StrategyDirectV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	actor, err := d.newForwardActor(context.Background(), spec, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("direct actor: %v", err)
	}
	if actor.acq != nil {
		t.Fatal("direct forward must not carry a manager acquisition")
	}
	if _, ok := actor.lease.(registryLease); !ok {
		t.Fatalf("direct lease = %T, want a registry lease", actor.lease)
	}
	if err := d.closeAll(context.Background()); err != nil {
		t.Fatalf("closeAll: %v", err)
	}
}
