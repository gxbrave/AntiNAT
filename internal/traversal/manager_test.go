package traversal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// Story 7 RED: the manager composes one Forward's TCP traversal acquisition
// with ownership-strength release and the §3.5 renewal contract (renew near
// 50% lifetime with jitter, three consecutive failures degrade, expiry
// margin or gateway reboot loses).

// fakeListenerSource is a scripted ListenerSource.
type fakeListenerSource struct {
	mu        sync.Mutex
	acquired  []TupleKey
	released  int
	acquireFn func(key TupleKey) (net.Listener, TupleKey, error)
}

func (f *fakeListenerSource) Acquire(ctx context.Context, owner string, key TupleKey) (net.Listener, TupleKey, ReleaseFunc, error) {
	f.mu.Lock()
	f.acquired = append(f.acquired, key)
	f.mu.Unlock()
	if f.acquireFn != nil {
		listener, actual, err := f.acquireFn(key)
		if err != nil {
			return nil, TupleKey{}, nil, err
		}
		return listener, actual, func() error {
			f.mu.Lock()
			f.released++
			f.mu.Unlock()
			return listener.Close()
		}, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, TupleKey{}, nil, err
	}
	return listener, TupleKey{Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, func() error {
		f.mu.Lock()
		f.released++
		f.mu.Unlock()
		return listener.Close()
	}, nil
}

func (f *fakeListenerSource) releaseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released
}

// scriptedMapper records renew/delete activity for the renewal tests.
type scriptedMapper struct {
	fakeMapper
	mu         sync.Mutex
	renewals   int
	deletes    int
	renewErr   error
	renewState GatewayMapping
}

func (s *scriptedMapper) Renew(ctx context.Context, mapping GatewayMapping, lifetime time.Duration) (GatewayMapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewals++
	if s.renewErr != nil {
		return GatewayMapping{}, s.renewErr
	}
	mapping.Lease = lifetime
	s.renewState = mapping
	return mapping, nil
}

func (s *scriptedMapper) Delete(ctx context.Context, mapping GatewayMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	return nil
}

func (s *scriptedMapper) renewalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewals
}

// managerRouteTable is the scripted route table (in-package helper).
type managerRouteTableImpl struct {
	addresses []IPv4Address
}

func (m managerRouteTableImpl) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("10.0.0.1"), "lan0", true, nil
}

func (m managerRouteTableImpl) IPv4Addresses() ([]IPv4Address, error) {
	return m.addresses, nil
}

func managerRouteTable() managerRouteTableImpl {
	return managerRouteTableImpl{
		addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}},
	}
}

// MA1: acquiring with an explicit-gateway plan composes the mapping layer,
// journals the record with honest ownership and yields the FIRST_HOP
// verdict for a non-global assignment.
func TestManagerAcquireExplicitGateway(t *testing.T) {
	mapper := &scriptedMapper{fakeMapper: fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}}
	journal := NewMemoryJournal()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})

	acquisition, err := manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "forward-1",
		Owner:     "forward-1",
		Spec: protocol.ForwardSpec{
			ForwardID: "forward-1", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway, RequestedPublicPort: 43111,
		},
		Plan: PlanRequest{
			Strategy:                protocol.StrategyExplicitGateway,
			MappingLayer:            LayerPCP,
			GatewayPortPolicy:       PortPolicyAcceptAny,
			FinalEndpointConstraint: PortPolicyAcceptAssigned,
		},
		Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	if acquisition.Verdict.Scope != ScopeFirstHop || acquisition.Verdict.PublicCandidate {
		t.Fatalf("verdict = %+v, want FIRST_HOP and no public candidate", acquisition.Verdict)
	}
	if acquisition.Mapping == nil || acquisition.Mapping.Mechanism != LayerPCP {
		t.Fatalf("mapping = %+v", acquisition.Mapping)
	}
	records, err := journal.ListByForward("forward-1")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v", records, err)
	}
	if records[0].Ownership != OwnershipStrong || records[0].ExternalPort != 43111 {
		t.Fatalf("journal record = %+v", records[0])
	}
	if acquisition.JournalID != records[0].ID {
		t.Fatalf("journal ref = %q, want %q", acquisition.JournalID, records[0].ID)
	}
	if len(acquisition.Layers) != 1 || acquisition.Layers[0].Kind != LayerKindGateway {
		t.Fatalf("layers = %+v", acquisition.Layers)
	}
}

// MA2: release deletes the mapping per ownership and releases the listener;
// the journal record is removed.
func TestManagerRelease(t *testing.T) {
	mapper := &scriptedMapper{fakeMapper: fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}}
	journal := NewMemoryJournal()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "forward-2",
		Owner:     "forward-2",
		Spec: protocol.ForwardSpec{
			ForwardID: "forward-2", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway,
		},
		Plan: PlanRequest{
			Strategy:     protocol.StrategyExplicitGateway,
			MappingLayer: LayerPCP,
		},
		Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if mapper.deletes != 1 {
		t.Fatalf("deletes = %d, want 1", mapper.deletes)
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want 1", got)
	}
	if _, ok, _ := journal.Get(acquisition.JournalID); ok {
		t.Fatal("released mapping must leave the journal")
	}
}

// MA3: direct-v4 acquisition requires a global source and yields the
// GLOBAL_PUBLIC probe-eligible verdict; the manual strategy requires the
// operator endpoint.
func TestManagerDirectAndManualPlans(t *testing.T) {
	privateRoute := managerRouteTableImpl{
		addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("192.168.1.10")}},
	}
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: privateRoute,
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{},
		Journal:    NewMemoryJournal(),
	})
	_, err := manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "f-direct",
		Owner:     "f-direct",
		Spec: protocol.ForwardSpec{
			ForwardID: "f-direct", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyDirectV4,
		},
		Plan: PlanRequest{Strategy: protocol.StrategyDirectV4},
	})
	var capabilityErr *CapabilityError
	if !errors.As(err, &capabilityErr) || capabilityErr.Capability != CapabilityNoGlobalV4Source {
		t.Fatalf("error = %v, want NO_GLOBAL_V4_SOURCE capability error", err)
	}

	globalRoute := managerRouteTable()
	globalRoute.addresses = []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("8.8.8.8")}}
	// The direct listener must bind the global source; without the alias
	// the bind itself fails, which is an honest skip on unprivileged hosts.
	if os.Geteuid() != 0 {
		t.Skip("direct-v4 global bind requires the global literal alias; run with sudo -E")
	}
	if out, err := exec.Command("ip", "addr", "add", "8.8.8.8/32", "dev", "lo").CombinedOutput(); err != nil && !strings.Contains(string(out), "Address already assigned") {
		t.Fatalf("alias global literal: %v\n%s", err, out)
	}
	defer exec.Command("ip", "addr", "del", "8.8.8.8/32", "dev", "lo").Run() //nolint:errcheck
	globalManager := NewManager(ManagerOptions{
		RouteTable: globalRoute,
		Listeners: &fakeListenerSource{acquireFn: func(key TupleKey) (net.Listener, TupleKey, error) {
			listener, err := net.Listen("tcp4", "8.8.8.8:0")
			if err != nil {
				return nil, TupleKey{}, err
			}
			return listener, TupleKey{Family: "ipv4", Protocol: "tcp",
				Address: "8.8.8.8", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, nil
		}},
		Mappers: map[MappingLayerKind]GatewayMapper{},
		Journal: NewMemoryJournal(),
	})
	acquisition, err := globalManager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "f-direct2",
		Owner:     "f-direct2",
		Spec: protocol.ForwardSpec{
			ForwardID: "f-direct2", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyDirectV4,
		},
		Plan: PlanRequest{Strategy: protocol.StrategyDirectV4},
	})
	if err != nil {
		t.Fatalf("direct acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	if !acquisition.Verdict.PublicCandidate || acquisition.Verdict.Scope != ScopeGlobalPublic {
		t.Fatalf("verdict = %+v, want probe-eligible GLOBAL_PUBLIC", acquisition.Verdict)
	}

	// Manual without operator endpoint refuses.
	_, err = manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "f-manual",
		Owner:     "f-manual",
		Spec: protocol.ForwardSpec{
			ForwardID: "f-manual", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyManualStaticV4,
		},
		Plan: PlanRequest{Strategy: protocol.StrategyManualStaticV4},
	})
	if !errors.Is(err, ErrOperatorEndpointRequired) {
		t.Fatalf("manual error = %v, want ErrOperatorEndpointRequired", err)
	}
}

// MA4: the renewal contract — renewals fire near 50% of the lease with
// jitter; three consecutive renewal failures surface the lost callback
// (publication goes stale per state-model §5), and the gateway reboot
// signal loses immediately.
func TestManagerRenewalLostAfterThreeFailures(t *testing.T) {
	mapper := &scriptedMapper{
		fakeMapper: fakeMapper{
			mechanism: LayerPCP,
			ownership: OwnershipStrong,
			control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
			external:  netip.MustParseAddrPort("100.64.0.2:43111"),
		},
		renewErr: errors.New("gateway gone"),
	}
	lost := make(chan string, 4)
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) {
			lost <- reason
		},
		// Test clock: renewal check every 20ms of simulated time.
		Clock: func() time.Time { return time.Now() },
	})
	acquisition, err := manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "forward-3",
		Owner:     "forward-3",
		Spec: protocol.ForwardSpec{
			ForwardID: "forward-3", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway,
		},
		Plan: PlanRequest{
			Strategy:     protocol.StrategyExplicitGateway,
			MappingLayer: LayerPCP,
		},
		Lease:            2 * time.Second,
		RenewalInterval:  20 * time.Millisecond, // test pacing
		RenewalJitterMax: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if reason == "" {
			t.Fatal("lost reason must not be empty")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("three consecutive renewal failures must surface the lost callback")
	}
	if got := mapper.renewalCount(); got < 3 {
		t.Fatalf("renewals = %d, want at least 3 failures before LOST", got)
	}
}

// MA5: a healthy mapping renews within the paced interval and stays quiet.
func TestManagerRenewalHealthy(t *testing.T) {
	mapper := &scriptedMapper{fakeMapper: fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}}
	lost := make(chan string, 1)
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) {
			lost <- reason
		},
	})
	acquisition, err := manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "forward-4",
		Owner:     "forward-4",
		Spec: protocol.ForwardSpec{
			ForwardID: "forward-4", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway,
		},
		Plan: PlanRequest{
			Strategy:     protocol.StrategyExplicitGateway,
			MappingLayer: LayerPCP,
		},
		Lease:            time.Hour,
		RenewalInterval:  20 * time.Millisecond,
		RenewalJitterMax: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	select {
	case reason := <-lost:
		t.Fatalf("healthy mapping must not be lost: %s", reason)
	default:
	}
	if got := mapper.renewalCount(); got == 0 {
		t.Fatal("healthy mapping must have renewed at least once")
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	renewalsAfterRelease := mapper.renewalCount()
	time.Sleep(60 * time.Millisecond)
	if mapper.renewalCount() != renewalsAfterRelease {
		t.Fatal("renewals must stop after release")
	}
}
