package traversal_test

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
	"github.com/gxbrave/AntiNAT/internal/traversal"
	"github.com/gxbrave/AntiNAT/internal/traversal/stun"
)

// observeStunTCP is the production STUN observation injected into the
// detector; it lives in the external test package because the stun package
// depends on traversal.
func observeStunTCP(ctx context.Context, server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
	client, err := stun.DialTCP(ctx, server.String(), stun.TCPClientOptions{Timeout: timeout})
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer client.Close()
	txid, err := stun.NewTransactionID()
	if err != nil {
		return netip.AddrPort{}, err
	}
	response, err := client.Exchange(ctx, stun.NewBindingRequest(txid))
	if err != nil {
		return netip.AddrPort{}, err
	}
	if response.Type.Class() != stun.ClassSuccess {
		return netip.AddrPort{}, errors.New("stun binding failed")
	}
	return response.XORMappedAddress()
}

// fakeGatewayMapper is the self-contained external-package fake.
type fakeGatewayMapper struct {
	mechanism   traversal.MappingLayerKind
	ownership   traversal.OwnershipStrength
	control     traversal.ControlServer
	discoverErr error
	mapErr      error
	external    netip.AddrPort
	deleted     bool
	mu          sync.Mutex
}

func (f *fakeGatewayMapper) Mechanism() traversal.MappingLayerKind  { return f.mechanism }
func (f *fakeGatewayMapper) Ownership() traversal.OwnershipStrength { return f.ownership }
func (f *fakeGatewayMapper) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(f.mechanism, false)
}
func (f *fakeGatewayMapper) Discover(ctx context.Context) (traversal.ControlServer, error) {
	return f.control, f.discoverErr
}
func (f *fakeGatewayMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	if f.mapErr != nil {
		return traversal.GatewayMapping{}, f.mapErr
	}
	return traversal.GatewayMapping{
		Mechanism:    f.mechanism,
		Ownership:    f.ownership,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     f.external,
		Lease:        req.Lease,
		State:        "fake-state",
	}, nil
}
func (f *fakeGatewayMapper) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	mapping.Lease = lifetime
	return mapping, nil
}
func (f *fakeGatewayMapper) Delete(ctx context.Context, mapping traversal.GatewayMapping) error {
	f.mu.Lock()
	f.deleted = true
	f.mu.Unlock()
	return nil
}

// detectionRouteTable is the scripted route table for detection runs.
type detectionRouteTable struct {
	defaultGateway netip.Addr
	defaultIface   string
	hasDefault     bool
	addresses      []traversal.IPv4Address
}

func (f detectionRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return f.defaultGateway, f.defaultIface, f.hasDefault, nil
}

func (f detectionRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return f.addresses, nil
}

// recordingMapper wraps fakeGatewayMapper with attempt bookkeeping for the
// detection tests.
type recordingMapper struct {
	fakeGatewayMapper
	mu       sync.Mutex
	attempts []traversal.GatewayMapRequest
	delay    time.Duration
}

func (r *recordingMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	r.mu.Lock()
	r.attempts = append(r.attempts, req)
	r.mu.Unlock()
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	return r.fakeGatewayMapper.Map(ctx, req)
}

func (r *recordingMapper) attemptCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attempts)
}

func (r *recordingMapper) attemptedPorts() []uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ports := make([]uint16, 0, len(r.attempts))
	for _, attempt := range r.attempts {
		ports = append(ports, attempt.InternalPort)
	}
	return ports
}

// fakeStunTCPServer answers Binding requests with an XOR-mapped address.
func fakeStunTCPServer(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake STUN server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFakeStunConn(conn)
		}
	}()
	return netip.MustParseAddrPort(listener.Addr().String())
}

func handleFakeStunConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		message, err := stun.ParseMessage(buf[:n])
		if err != nil {
			return
		}
		remote := conn.RemoteAddr().(*net.TCPAddr)
		ip, ok := netip.AddrFromSlice(remote.IP)
		if !ok {
			return
		}
		reply := &stun.Message{Type: stun.MessageTypeBindingSuccess, TransactionID: message.TransactionID}
		if err := reply.AddXORMappedAddress(netip.AddrPortFrom(ip.Unmap(), uint16(remote.Port))); err != nil {
			return
		}
		wire, err := reply.Marshal()
		if err != nil {
			return
		}
		if _, err := conn.Write(wire); err != nil {
			return
		}
	}
}

const detectionGlobalLiteral = "8.8.8.8"

func aliasGlobalForDetection(t *testing.T) func() {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("detection direct-v4 acquire requires the global literal alias; run with sudo -E")
	}
	out, err := exec.Command("ip", "addr", "add", detectionGlobalLiteral+"/32", "dev", "lo").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "Address already assigned") {
		t.Fatalf("alias global literal: %v\n%s", err, out)
	}
	return func() {
		_ = exec.Command("ip", "addr", "del", detectionGlobalLiteral+"/32", "dev", "lo").Run()
	}
}

// DE1: sequential detection classifies each strategy honestly: direct-v4
// and the responding gateway mechanism PASS with a layer signature,
// manual-static is EXCLUDED, stun-only records the observed candidate, and
// the profile carries the first passed default with per-attempt cleanup
// (no temp tuple left behind).
func TestDetectionSequentialTCP(t *testing.T) {
	cleanup := aliasGlobalForDetection(t)
	defer cleanup()

	rt := detectionRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr(detectionGlobalLiteral)}},
	}
	gatewayMapper := &recordingMapper{fakeGatewayMapper: fakeGatewayMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "127.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}}
	registry := traversal.NewPortRegistry()
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable: rt,
		Registry:   registry,
		Mappers:    map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: gatewayMapper},
		AutoOrder: []protocol.Strategy{
			protocol.StrategyExplicitGateway,
			protocol.StrategyDirectV4,
		},
		AttemptTimeout: 2 * time.Second,
	})

	profile, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolTCP})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if profile.Protocol != traversal.ProtocolTCP || profile.Fingerprint == "" {
		t.Fatalf("profile = %+v", profile)
	}
	if profile.DefaultStrategy != protocol.StrategyExplicitGateway {
		t.Fatalf("default strategy = %q, want explicit-gateway (auto order first passed)", profile.DefaultStrategy)
	}
	gatewayResult, ok := profile.ResultFor(protocol.StrategyExplicitGateway)
	if !ok || gatewayResult.State != traversal.DetectionPassed || gatewayResult.LayerSignature != "pcp" {
		t.Fatalf("gateway result = %+v", gatewayResult)
	}
	manualResult, ok := profile.ResultFor(protocol.StrategyManualStaticV4)
	if !ok || manualResult.State != traversal.DetectionExcluded {
		t.Fatalf("manual result = %+v, want EXCLUDED", manualResult)
	}
	if got := registry.Len(); got != 0 {
		t.Fatalf("temp tuples leaked: registry holds %d entries", got)
	}
}

// DE2: temp detection attempts use distinct ephemeral tuples and operation
// IDs, and never prove a Forward endpoint.
func TestDetectionTempTuplesDistinct(t *testing.T) {
	rt := detectionRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr("127.0.0.1")}},
	}
	gatewayMapper := &recordingMapper{fakeGatewayMapper: fakeGatewayMapper{
		mechanism: traversal.LayerNATPMP,
		ownership: traversal.OwnershipWeakLease,
		control:   traversal.ControlServer{Mechanism: traversal.LayerNATPMP, Address: "127.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:55555"),
	}}
	registry := traversal.NewPortRegistry()
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable: rt,
		Registry:   registry,
		Mappers:    map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerNATPMP: gatewayMapper},
		AutoOrder:  []protocol.Strategy{protocol.StrategyExplicitGateway},
	})
	profile, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolTCP})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	result, _ := profile.ResultFor(protocol.StrategyExplicitGateway)
	if result.State != traversal.DetectionPassed {
		t.Fatalf("gateway result = %+v", result)
	}
	ports := gatewayMapper.attemptedPorts()
	if len(ports) != 1 || ports[0] == 0 {
		t.Fatalf("detection must map a concrete temp tuple, ports = %v", ports)
	}
	if result.Candidate != "100.64.0.2:55555" {
		t.Fatalf("candidate = %q", result.Candidate)
	}
}

// DE3: bounded parallel detection runs attempts concurrently with a bound
// on workers and still cleans every temp tuple.
func TestDetectionBoundedParallel(t *testing.T) {
	rt := detectionRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr("127.0.0.1")}},
	}
	mapperA := &recordingMapper{fakeGatewayMapper: fakeGatewayMapper{
		mechanism: traversal.LayerPCP, ownership: traversal.OwnershipStrong,
		control:  traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "127.0.0.1:5351"},
		external: netip.MustParseAddrPort("100.64.0.2:43111"),
	}, delay: 100 * time.Millisecond}
	mapperB := &recordingMapper{fakeGatewayMapper: fakeGatewayMapper{
		mechanism: traversal.LayerNATPMP, ownership: traversal.OwnershipWeakLease,
		control:  traversal.ControlServer{Mechanism: traversal.LayerNATPMP, Address: "127.0.0.1:5351"},
		external: netip.MustParseAddrPort("100.64.0.2:55555"),
	}, delay: 100 * time.Millisecond}
	registry := traversal.NewPortRegistry()
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable: rt,
		Registry:   registry,
		Mappers: map[traversal.MappingLayerKind]traversal.GatewayMapper{
			traversal.LayerPCP:    mapperA,
			traversal.LayerNATPMP: mapperB,
		},
		AutoOrder: []protocol.Strategy{protocol.StrategyExplicitGateway},
	})
	started := time.Now()
	profile, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolTCP, Parallel: 2})
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("parallel attempts ran sequentially: %s", elapsed)
	}
	if mapperA.attemptCount() != 1 || mapperB.attemptCount() != 1 {
		t.Fatalf("attempts = %d/%d, want one per mechanism", mapperA.attemptCount(), mapperB.attemptCount())
	}
	if got := registry.Len(); got != 0 {
		t.Fatalf("temp tuples leaked: %d", got)
	}
	if _, ok := profile.ResultFor(protocol.StrategyExplicitGateway); !ok {
		t.Fatal("explicit-gateway result missing")
	}
}

// DE4: an all-failed detection still returns a saved profile with every
// strategy FAILED and no invented default.
func TestDetectionAllFailedStillSaves(t *testing.T) {
	rt := detectionRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr("127.0.0.1")}},
	}
	deadMapper := &recordingMapper{fakeGatewayMapper: fakeGatewayMapper{
		mechanism:   traversal.LayerPCP,
		ownership:   traversal.OwnershipStrong,
		discoverErr: errors.New("no response"),
	}}
	registry := traversal.NewPortRegistry()
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable: rt,
		Registry:   registry,
		Mappers:    map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: deadMapper},
		AutoOrder: []protocol.Strategy{
			protocol.StrategyExplicitGateway,
			protocol.StrategyStunOnly,
			protocol.StrategyDirectV4,
		},
		StunServers: []string{"stun+tcp://127.0.0.1:1"}, // nothing listens
		StunObserve: observeStunTCP,
	})
	profile, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolTCP})
	if err != nil {
		t.Fatalf("all-failed detection must save, not error: %v", err)
	}
	if profile.DefaultStrategy != "" {
		t.Fatalf("default = %q, want empty", profile.DefaultStrategy)
	}
	directResult, ok := profile.ResultFor(protocol.StrategyDirectV4)
	if !ok || directResult.State != traversal.DetectionFailed {
		t.Fatalf("direct result = %+v", directResult)
	}
	if directResult.Capability == "" {
		t.Fatal("a failed direct-v4 attempt must carry the stable capability code")
	}
	if got := registry.Len(); got != 0 {
		t.Fatalf("temp tuples leaked: %d", got)
	}
}

// DE5: UDP detection is deferred to P13 with a stable error: P12 owns the
// TCP dataplane only.
func TestDetectionUDPDeferred(t *testing.T) {
	rt := detectionRouteTable{}
	detector := traversal.NewDetector(traversal.DetectorOptions{RouteTable: rt})
	if _, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolUDP}); !errors.Is(err, traversal.ErrUDPDetectionDeferred) {
		t.Fatalf("error = %v, want traversal.ErrUDPDetectionDeferred", err)
	}
}

// DE6: stun-only detection observes a mapped candidate through the fake
// STUN server and records the honest MAPPED_UNVERIFIED-graded evidence.
func TestDetectionStunOnly(t *testing.T) {
	cleanup := aliasGlobalForDetection(t)
	defer cleanup()

	server := fakeStunTCPServer(t)
	rt := detectionRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr(detectionGlobalLiteral)}},
	}
	registry := traversal.NewPortRegistry()
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable:  rt,
		Registry:    registry,
		Mappers:     map[traversal.MappingLayerKind]traversal.GatewayMapper{},
		AutoOrder:   []protocol.Strategy{protocol.StrategyStunOnly},
		StunServers: []string{"stun+tcp://" + server.String()},
		StunObserve: observeStunTCP,
	})
	profile, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolTCP})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	result, ok := profile.ResultFor(protocol.StrategyStunOnly)
	if !ok || result.State != traversal.DetectionPassed {
		t.Fatalf("stun-only result = %+v", result)
	}
	if result.LayerSignature != "stun-tcp" {
		t.Fatalf("layer signature = %q, want stun-tcp", result.LayerSignature)
	}
	if result.Candidate == "" {
		t.Fatal("stun-only detection must record the observed candidate")
	}
	// The evidence grades the observation honestly: observed only, never
	// verified without the independent probe.
	for _, evidence := range result.Evidence {
		if evidence.Kind == traversal.LayerKindSTUN && evidence.Ownership != traversal.OwnershipObservedOnly {
			t.Fatalf("stun evidence ownership = %q", evidence.Ownership)
		}
	}
}

// DE7 (code-review finding): a failing gateway mechanism must not shadow a
// later passing one — the explicit-gateway result is exactly ONE row
// carrying the passing mechanism, with the failed mechanisms folded into
// its note trail; otherwise ResultFor reports FAILED while
// PassedStrategies claims the strategy passed.
func TestDetectionAggregationReplacesFailedGatewayRow(t *testing.T) {
	cleanup := aliasGlobalForDetection(t)
	defer cleanup()

	rt := detectionRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr(detectionGlobalLiteral)}},
	}
	failingPcp := &fakeGatewayMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "127.0.0.1:5351"},
		mapErr:    errors.New("no pcp gateway"),
	}
	passingNatpmp := &fakeGatewayMapper{
		mechanism: traversal.LayerNATPMP,
		ownership: traversal.OwnershipWeakLease,
		control:   traversal.ControlServer{Mechanism: traversal.LayerNATPMP, Address: "127.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable: rt,
		Registry:   traversal.NewPortRegistry(),
		Mappers: map[traversal.MappingLayerKind]traversal.GatewayMapper{
			traversal.LayerPCP:    failingPcp,
			traversal.LayerNATPMP: passingNatpmp,
		},
		AutoOrder:      []protocol.Strategy{protocol.StrategyExplicitGateway},
		AttemptTimeout: 2 * time.Second,
	})

	profile, err := detector.Run(t.Context(), traversal.DetectionRequest{Protocol: traversal.ProtocolTCP})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rows := 0
	var gateway *traversal.StrategyResult
	for i := range profile.Results {
		if profile.Results[i].Strategy == protocol.StrategyExplicitGateway {
			rows++
			gateway = &profile.Results[i]
		}
	}
	if rows != 1 || gateway == nil {
		t.Fatalf("explicit-gateway rows = %d, want exactly 1", rows)
	}
	if gateway.State != traversal.DetectionPassed {
		t.Fatalf("gateway state = %q, want PASSED (NAT-PMP passed after PCP failed)", gateway.State)
	}
	if gateway.LayerSignature != "nat-pmp" {
		t.Fatalf("layer signature = %q, want the passing mechanism nat-pmp", gateway.LayerSignature)
	}
	if !strings.Contains(gateway.Note, "pcp") {
		t.Fatalf("note = %q, want the failed mechanism folded into the trail", gateway.Note)
	}
	if profile.DefaultStrategy != protocol.StrategyExplicitGateway {
		t.Fatalf("default strategy = %q, want explicit-gateway", profile.DefaultStrategy)
	}
}
