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

// Story 7 RED/2: the manager composes one Forward's TCP traversal
// acquisition with ownership-strength release and the §3.5 renewal
// contract: renew near 50% of the GRANTED lease with jitter, three
// consecutive failures degrade (DEGRADED), the expiry safety margin, a
// confirmed gateway reboot or a rewritten external endpoint loses, the
// journal carries the mechanism-private renewal state, and Release is
// idempotent while never destroying the only record of a mapping it could
// not delete.

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

func (f *fakeListenerSource) acquiredKeys() []TupleKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]TupleKey(nil), f.acquired...)
}

// scriptedMapper records renew/delete activity and scripts the §3.5 ladder
// outcomes: renewal failures, a confirmed reboot, a rewritten external
// endpoint and a granted-shorter-than-requested lease.
type scriptedMapper struct {
	fakeMapper
	mu                   sync.Mutex
	renewals             int
	deletes              int
	renewErr             error
	deleteErr            error
	rebootAfter          int // renewal ordinal (1-based) reporting ServerRebooted; 0 = never
	rewriteExternalAfter int // renewal ordinal rewriting the external endpoint; 0 = never
	rewrittenExternal    netip.AddrPort
	grantedLease         time.Duration // granted lease overriding the request; 0 = grant the request
}

// Map shadows the embedded fake mapper to apply the scripted grant.
func (s *scriptedMapper) Map(ctx context.Context, req GatewayMapRequest) (GatewayMapping, error) {
	mapping, err := s.fakeMapper.Map(ctx, req)
	if err != nil {
		return mapping, err
	}
	if s.grantedLease > 0 {
		mapping.Lease = s.grantedLease
	}
	return mapping, nil
}

func (s *scriptedMapper) Renew(ctx context.Context, mapping GatewayMapping, lifetime time.Duration) (GatewayMapping, error) {
	s.mu.Lock()
	s.renewals++
	renewals := s.renewals
	renewErr, rebootAfter, rewriteAfter, granted := s.renewErr, s.rebootAfter, s.rewriteExternalAfter, s.grantedLease
	s.mu.Unlock()
	if renewErr != nil {
		return GatewayMapping{}, renewErr
	}
	mapping.Lease = lifetime
	if granted > 0 {
		mapping.Lease = granted
	}
	if rebootAfter > 0 && renewals >= rebootAfter {
		mapping.ServerRebooted = true
	}
	if rewriteAfter > 0 && renewals >= rewriteAfter {
		mapping.External = s.rewrittenExternal
	}
	return mapping, nil
}

func (s *scriptedMapper) Delete(ctx context.Context, mapping GatewayMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	return s.deleteErr
}

func (s *scriptedMapper) renewalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewals
}

func (s *scriptedMapper) deleteCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletes
}

func (s *scriptedMapper) setRenewErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewErr = err
}

// failingJournal fails every Put (durable-store IO error).
type failingJournal struct {
	*MemoryJournal
	putErr error
}

func (f *failingJournal) Put(record JournalRecord) error { return f.putErr }

// stepClock advances a fixed step on every read: journal timestamps and
// lease deadlines become observable without real-time waits.
type stepClock struct {
	mu   sync.Mutex
	cur  time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cur = c.cur.Add(c.step)
	return c.cur
}

// managerRouteTable is the scripted route table (in-package helper): the
// default-route interface holds the PRIVATE address 10.0.0.2 — the normal
// shape behind a NAT CPE.
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

// gatewayMapperFixture is the scripted PCP mapper every acquisition test
// starts from.
func gatewayMapperFixture() *scriptedMapper {
	return &scriptedMapper{fakeMapper: fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}}
}

func gatewayAcquireRequest(forwardID string) AcquireRequest {
	return AcquireRequest{
		ForwardID: forwardID,
		Owner:     forwardID,
		Spec: protocol.ForwardSpec{
			ForwardID: forwardID, Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway,
		},
		Plan: PlanRequest{
			Strategy:     protocol.StrategyExplicitGateway,
			MappingLayer: LayerPCP,
		},
	}
}

// withPacing injects the fast test renewal interval through the request.
func withPacing(request AcquireRequest, interval time.Duration) AcquireRequest {
	request.RenewalInterval = interval
	request.RenewalJitterMax = time.Millisecond
	return request
}

// MA1: acquiring with an explicit-gateway plan composes the mapping layer,
// binds the default-route interface's own (private) address — never the
// 127.0.0.1 fallback — journals the record with honest ownership, the
// serialized renewal state, and yields the FIRST_HOP verdict for a
// non-global assignment.
func TestManagerAcquireExplicitGateway(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := NewMemoryJournal()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})

	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-1"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	keys := listeners.acquiredKeys()
	if len(keys) != 1 || keys[0].Address != "10.0.0.2" {
		t.Fatalf("listener keys = %+v, want the private default-route source 10.0.0.2", keys)
	}
	if acquisition.Mapping == nil || acquisition.Mapping.Mechanism != LayerPCP {
		t.Fatalf("mapping = %+v", acquisition.Mapping)
	}
	if acquisition.Mapping.InternalIP.String() != "10.0.0.2" {
		t.Fatalf("mapping internal IP = %s, want 10.0.0.2", acquisition.Mapping.InternalIP)
	}
	if acquisition.Verdict.Scope != ScopeFirstHop || acquisition.Verdict.PublicCandidate {
		t.Fatalf("verdict = %+v, want FIRST_HOP and no public candidate", acquisition.Verdict)
	}
	records, err := journal.ListByForward("forward-1")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v", records, err)
	}
	if records[0].Ownership != OwnershipStrong || records[0].ExternalPort != 43111 {
		t.Fatalf("journal record = %+v", records[0])
	}
	if records[0].InternalIP != "10.0.0.2" {
		t.Fatalf("journal internal IP = %s, want 10.0.0.2", records[0].InternalIP)
	}
	// The mechanism-private renewal state is journaled: the fake mapper's
	// State "fake-state" must serialize to the quoted JSON string, so
	// recovery can renew or release after a restart.
	if string(records[0].State) != `"fake-state"` {
		t.Fatalf("journal state = %q, want the serialized ownership state", records[0].State)
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
	mapper := gatewayMapperFixture()
	journal := NewMemoryJournal()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-2"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("deletes = %d, want 1", mapper.deleteCount())
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

// MA4: Release is idempotent — the second call re-deletes nothing and
// returns the first outcome.
func TestManagerReleaseIdempotent(t *testing.T) {
	mapper := gatewayMapperFixture()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-idem"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("second Release must return the first (clean) outcome: %v", err)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("deletes = %d, want exactly 1 across both releases", mapper.deleteCount())
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want exactly 1", got)
	}
}

// MA5: three consecutive renewal failures degrade the mapping (keepalive
// DEGRADED) — the lost callback must NOT fire while renewals continue, the
// lease margin (1h/10) is far away.
func TestManagerRenewalDegradesAfterThreeFailures(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	degraded := make(chan string, 4)
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:        managerRouteTable(),
		Listeners:         &fakeListenerSource{},
		Mappers:           map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:           NewMemoryJournal(),
		OnMappingDegraded: func(forwardID string, reason string) { degraded <- reason },
		OnMappingLost:     func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-3"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-degraded:
		if reason == "" {
			t.Fatal("degraded reason must not be empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("three consecutive renewal failures must fire the degraded callback")
	}
	select {
	case reason := <-lost:
		t.Fatalf("a degraded mapping is not lost while the lease margin is far: %s", reason)
	case <-time.After(300 * time.Millisecond):
	}
	// Renewals continue after DEGRADED: the mapping may still recover.
	first := mapper.renewalCount()
	deadline := time.Now().Add(500 * time.Millisecond)
	for mapper.renewalCount() <= first && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mapper.renewalCount() <= first {
		t.Fatal("renewals must continue after DEGRADED")
	}
}

// MA6: sustained failures crossing the expiry safety margin lose the
// mapping and stop the renewal loop.
func TestManagerRenewalLostAtExpiryMargin(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	request := gatewayAcquireRequest("forward-4")
	request.Lease = 2 * time.Second // margin = lease/10 = 200ms
	acquisition, err := manager.Acquire(t.Context(), withPacing(request, 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if !strings.Contains(reason, "margin") {
			t.Fatalf("lost reason = %q, want the expiry safety margin crossing", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the expiry safety margin must lose the mapping")
	}
	// The renewal loop stops after LOST.
	time.Sleep(150 * time.Millisecond)
	stable := mapper.renewalCount()
	time.Sleep(150 * time.Millisecond)
	if mapper.renewalCount() != stable {
		t.Fatal("renewals must stop after LOST")
	}
}

// MA7: a successful renewal after DEGRADED recovers (HEALTHY) — the
// recovered callback fires once and a fresh failure streak can degrade
// again.
func TestManagerRenewalRecoversAfterDegraded(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	degraded := make(chan string, 4)
	recovered := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:         managerRouteTable(),
		Listeners:          &fakeListenerSource{},
		Mappers:            map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:            NewMemoryJournal(),
		OnMappingDegraded:  func(forwardID string, reason string) { degraded <- reason },
		OnMappingRecovered: func(forwardID string) { recovered <- forwardID },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-5"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case <-degraded:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the degraded callback first")
	}
	mapper.setRenewErr(nil)
	select {
	case forwardID := <-recovered:
		if forwardID != "forward-5" {
			t.Fatalf("recovered forward = %q", forwardID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a successful renewal after DEGRADED must fire the recovered callback")
	}
}

// MA8: a confirmed gateway reboot (epoch rollback) loses immediately and
// stops the renewal loop.
func TestManagerRenewalRebootLosesImmediately(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.rebootAfter = 2
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-6"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if !strings.Contains(reason, "reboot") {
			t.Fatalf("lost reason = %q, want the gateway reboot signal", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a confirmed reboot must lose immediately")
	}
	time.Sleep(120 * time.Millisecond)
	stable := mapper.renewalCount()
	time.Sleep(120 * time.Millisecond)
	if mapper.renewalCount() != stable {
		t.Fatal("renewals must stop after a reboot loss")
	}
}

// MA9: a renewal that rewrites the external endpoint under a live
// acquisition is a loss — the published endpoint is no longer the mapped
// one (RFC 6887 §11.5).
func TestManagerRenewalEndpointChangeLoses(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.rewriteExternalAfter = 2
	mapper.rewrittenExternal = netip.MustParseAddrPort("100.64.0.2:9999")
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-7"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if !strings.Contains(reason, "endpoint") {
			t.Fatalf("lost reason = %q, want the rewritten external endpoint", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a rewritten external endpoint must lose the mapping")
	}
}

// MA10: renewal pacing adopts the GRANTED lease (§3.5: the granted
// lifetime is authoritative) — a short grant accelerates renewals without
// explicit test pacing.
func TestManagerRenewalPacesFromGrantedLease(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.grantedLease = 300 * time.Millisecond // requested 1h below
	lost := make(chan string, 1)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	request := gatewayAcquireRequest("forward-8")
	request.Lease = time.Hour
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	// Granted 300ms paces renewals at ~150ms: at least three within 1s.
	deadline := time.Now().Add(1 * time.Second)
	for mapper.renewalCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := mapper.renewalCount(); got < 3 {
		t.Fatalf("renewals = %d in 1s with a 300ms grant, want >= 3 (pacing must adopt the granted lease)", got)
	}
	select {
	case reason := <-lost:
		t.Fatalf("a healthy short-lease mapping must not be lost: %s", reason)
	default:
	}
}

// MA11: a healthy mapping renews within the paced interval and stays quiet.
func TestManagerRenewalHealthy(t *testing.T) {
	mapper := gatewayMapperFixture()
	lost := make(chan string, 1)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-9"), 20*time.Millisecond))
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

// MA12: journal renewals never rewrite the record's creation time — the
// step clock makes every write land on a distinct second.
func TestManagerJournalCreatedAtStable(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := NewMemoryJournal()
	clock := &stepClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
		Clock:      clock.Now,
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-10"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	createdAt := func() int64 {
		records, err := journal.ListByForward("forward-10")
		if err != nil || len(records) != 1 {
			t.Fatalf("journal records = %v/%v", records, err)
		}
		return records[0].CreatedAtUnix
	}
	first := createdAt()
	deadline := time.Now().Add(300 * time.Millisecond)
	for mapper.renewalCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mapper.renewalCount() < 3 {
		t.Fatal("expected renewals before checking timestamps")
	}
	records, err := journal.ListByForward("forward-10")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v", records, err)
	}
	if records[0].CreatedAtUnix != first {
		t.Fatalf("CreatedAtUnix = %d after renewals, want the original %d", records[0].CreatedAtUnix, first)
	}
	if records[0].UpdatedAtUnix == records[0].CreatedAtUnix {
		t.Fatal("renewals must update UpdatedAtUnix")
	}
}

// MA13: a failed journal write leaves no mapping_journal_ref — the
// reference must never name a record that was never persisted.
func TestManagerJournalPutFailureLeavesNoRef(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal(), putErr: errors.New("disk full")}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-11"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	if acquisition.JournalID != "" {
		t.Fatalf("journal ref = %q after a failed Put, want empty", acquisition.JournalID)
	}
}

// MA14: a failed mapping delete keeps the journal record — it is the only
// durable evidence of a mapping that may still be live.
func TestManagerReleaseKeepsJournalOnDeleteFailure(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.deleteErr = errors.New("gateway refused the delete")
	journal := NewMemoryJournal()
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-12"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err == nil {
		t.Fatal("a failed mapping delete must surface on Release")
	}
	if _, ok, _ := journal.Get(acquisition.JournalID); !ok {
		t.Fatal("the journal record must survive a failed mapping delete")
	}
}
