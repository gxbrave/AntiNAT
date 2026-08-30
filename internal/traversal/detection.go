// Node capability detection (v0.8 §3.2): sequential by default, bounded
// parallel on request, every attempt on its own temporary tuple with its
// own operation ID and a cleanup path that runs even on failure. Temp
// detection only proves capability — it never produces a Forward endpoint;
// every Forward acquires, keeps alive and probes independently.
// manual-static-v4 is excluded from automatic detection (operator input
// only), and UDP detection is deferred to P13 (UDP dataplane).
package traversal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ErrUDPDetectionDeferred is the stable outcome for UDP detection until P13
// ships the UDP dataplane.
var ErrUDPDetectionDeferred = errors.New("traversal: UDP capability detection is deferred to P13 (UDP dataplane)")

// DefaultAttemptTimeout bounds one detection attempt.
const DefaultAttemptTimeout = 3 * time.Second

// DetectionLease is the short mapping lease used for temp detection tuples;
// the cleanup path deletes the mapping, the lease only bounds leak damage.
const DetectionLease = 2 * time.Minute

// DetectorOptions configure the detector.
type DetectorOptions struct {
	RouteTable RouteTable
	// Mappers are the available gateway mechanisms; discovery failures are
	// evidence of absence, not fatal errors.
	Mappers map[MappingLayerKind]GatewayMapper
	// Registry is the port registry for temp tuples; nil allocates a
	// private one (tests use the field to assert leak-free cleanup).
	Registry *PortRegistry
	// AutoOrder is the node's declared auto strategy order for the default
	// selection.
	AutoOrder []protocol.Strategy
	// StunServers are the stun+tcp:// endpoints for stun-only detection.
	StunServers []string
	// StunObserve performs one transport-correct STUN observation from a
	// temp socket and returns the XOR-mapped endpoint. The seam exists
	// because the stun package depends on traversal (the observation
	// helpers live there), so traversal cannot import stun; the
	// composition root injects the implementation.
	StunObserve func(ctx context.Context, server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error)
	// AttemptTimeout bounds one attempt; default 3s.
	AttemptTimeout time.Duration
}

// Detector runs capability detection for one node.
type Detector struct {
	opts     DetectorOptions
	registry *PortRegistry
}

// DetectionRequest parameterizes one detection run.
type DetectionRequest struct {
	Protocol string // ProtocolTCP in v1; ProtocolUDP is deferred
	// Parallel bounds concurrent attempts; 0/1 is the sequential default.
	Parallel int
	// AttemptTimeout overrides the per-attempt budget.
	AttemptTimeout time.Duration
}

// NewDetector builds a detector.
func NewDetector(opts DetectorOptions) *Detector {
	if opts.AttemptTimeout <= 0 {
		opts.AttemptTimeout = DefaultAttemptTimeout
	}
	registry := opts.Registry
	if registry == nil {
		registry = NewPortRegistry()
	}
	return &Detector{opts: opts, registry: registry}
}

// Run performs one detection pass and always returns a saved profile on a
// successful run — even when every strategy failed. A protocol error
// (UDP deferral, unknown protocol) is the only error path.
func (d *Detector) Run(ctx context.Context, req DetectionRequest) (Profile, error) {
	switch req.Protocol {
	case ProtocolUDP:
		return Profile{}, ErrUDPDetectionDeferred
	case ProtocolTCP:
	default:
		return Profile{}, fmt.Errorf("traversal: unknown detection protocol %q", req.Protocol)
	}

	fingerprint, err := Fingerprint(d.opts.RouteTable)
	if err != nil {
		return Profile{}, fmt.Errorf("traversal: detection fingerprint: %w", err)
	}

	attemptTimeout := req.AttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = d.opts.AttemptTimeout
	}

	// One attempt per independent probe: direct-v4, one per gateway
	// mechanism, stun-only. Deterministic ordering keeps the profile
	// stable regardless of execution order.
	type attempt struct {
		name string
		run  func(ctx context.Context) StrategyResult
	}
	var attempts []attempt
	attempts = append(attempts, attempt{name: "direct-v4", run: d.directAttempt})
	for _, mechanism := range []MappingLayerKind{LayerPCP, LayerNATPMP, LayerUPnP} {
		mapper, ok := d.opts.Mappers[mechanism]
		if !ok {
			continue
		}
		attempts = append(attempts, attempt{
			name: string(mechanism),
			run:  d.gatewayAttempt(mechanism, mapper),
		})
	}
	attempts = append(attempts, attempt{name: "stun-only", run: d.stunAttempt})

	results := make([]StrategyResult, len(attempts))
	var resultMu sync.Mutex

	runAttempt := func(index int) {
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		defer cancel()
		result := attempts[index].run(attemptCtx)
		resultMu.Lock()
		results[index] = result
		resultMu.Unlock()
	}

	if parallel := req.Parallel; parallel > 1 {
		semaphore := make(chan struct{}, parallel)
		var wg sync.WaitGroup
		for i := range attempts {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				runAttempt(index)
			}(i)
		}
		wg.Wait()
	} else {
		for i := range attempts {
			runAttempt(i)
		}
	}

	profile := Profile{
		Fingerprint:    fingerprint,
		Protocol:       req.Protocol,
		ComputedAtUnix: time.Now().Unix(),
	}
	// Aggregate: explicit-gateway's result is the first passing mechanism
	// in deterministic order; direct-v4 and stun-only map one to one.
	gatewayPassed := false
	for i, attempt := range attempts {
		result := results[i]
		switch {
		case attempt.name == string(LayerPCP) || attempt.name == string(LayerNATPMP) ||
			attempt.name == string(LayerUPnP) || attempt.name == "upnp-igd:2" || attempt.name == "upnp-igd:1":
			if gatewayPassed {
				// A later mechanism's evidence folds into the winning
				// result's note trail only.
				continue
			}
			if result.State == DetectionPassed {
				gatewayPassed = true
				profile.Results = append(profile.Results, StrategyResult{
					Strategy:       protocol.StrategyExplicitGateway,
					State:          DetectionPassed,
					LayerSignature: result.LayerSignature,
					Evidence:       result.Evidence,
					Candidate:      result.Candidate,
					Note:           result.Note,
					StartedAtUnix:  result.StartedAtUnix,
					FinishedAtUnix: result.FinishedAtUnix,
				})
			} else {
				// Keep the first mechanism failure as the strategy result
				// seed; subsequent failures append their notes.
				merged, ok := profile.ResultFor(protocol.StrategyExplicitGateway)
				if !ok {
					merged = StrategyResult{Strategy: protocol.StrategyExplicitGateway, State: DetectionFailed}
				}
				merged.Note = strings.TrimSpace(merged.Note + " " + attempt.name + ": " + result.Note)
				profile.Results = replaceOrAppend(profile.Results, protocol.StrategyExplicitGateway, merged)
			}
		case attempt.name == "direct-v4":
			result.Strategy = protocol.StrategyDirectV4
			profile.Results = append(profile.Results, result)
		case attempt.name == "stun-only":
			result.Strategy = protocol.StrategyStunOnly
			profile.Results = append(profile.Results, result)
		}
	}

	// manual-static is never auto-detected.
	profile.Results = append(profile.Results, StrategyResult{
		Strategy: protocol.StrategyManualStaticV4,
		State:    DetectionExcluded,
		Note:     "manual-static-v4 is operator-configured only and never auto-detected",
	})

	// Default strategy: the first PASSED strategy in the declared auto
	// order; all-failed profiles stay empty.
	_, err = ResolveAuto(d.opts.AutoOrder, func(strategy protocol.Strategy) bool {
		result, ok := profile.ResultFor(strategy)
		return ok && result.State == DetectionPassed
	})
	if err == nil {
		for _, strategy := range d.opts.AutoOrder {
			if result, ok := profile.ResultFor(strategy); ok && result.State == DetectionPassed {
				profile.DefaultStrategy = strategy
				break
			}
		}
	}
	return profile, nil
}

// directAttempt proves the direct-v4 capability on a temp tuple.
func (d *Detector) directAttempt(ctx context.Context) StrategyResult {
	result := StrategyResult{StartedAtUnix: time.Now().Unix()}
	defer func() { result.FinishedAtUnix = time.Now().Unix() }()

	selection, capability, err := Assess(d.opts.RouteTable)
	if err != nil {
		result.State = DetectionFailed
		if capability != "" {
			result.Capability = string(capability)
		}
		result.Note = err.Error()
		return result
	}
	if !selection.Global {
		result.State = DetectionFailed
		result.Capability = string(CapabilityNoGlobalV4Source)
		result.Note = "selected interface has no global IPv4 source"
		return result
	}
	lease, err := d.registry.Acquire(ctx, "detection:"+d.operationID(), TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: selection.Source.String(), Port: 0,
	})
	if err != nil {
		result.State = DetectionFailed
		result.Note = "temp tuple acquire: " + err.Error()
		return result
	}
	defer lease.Release() //nolint:errcheck // cleanup path, error is incidental

	candidate := netip.AddrPortFrom(selection.Source, lease.Actual.Port)
	result.State = DetectionPassed
	result.Capability = string(CapabilityDirectV4Ready)
	result.Candidate = candidate.String()
	result.Evidence = []LayerEvidence{{
		Kind:             LayerKindDirect,
		InternalEndpoint: candidate.String(),
		AssignedEndpoint: candidate.String(),
		Scope:            ScopeGlobalPublic,
		Ownership:        OwnershipNotApplicable,
		ParentLayer:      -1,
	}}
	return result
}

// gatewayAttempt proves one gateway mechanism on a temp tuple.
func (d *Detector) gatewayAttempt(mechanism MappingLayerKind, mapper GatewayMapper) func(ctx context.Context) StrategyResult {
	return func(ctx context.Context) StrategyResult {
		result := StrategyResult{StartedAtUnix: time.Now().Unix()}
		defer func() { result.FinishedAtUnix = time.Now().Unix() }()

		control, err := mapper.Discover(ctx)
		if err != nil {
			result.State = DetectionFailed
			result.Note = "discovery: " + err.Error()
			return result
		}

		// Temp tuple for the mapping: bind the selected source (or
		// loopback in labs) on an ephemeral port.
		source := d.tempSource()
		lease, err := d.registry.Acquire(ctx, "detection:"+d.operationID(), TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: source.String(), Port: 0,
		})
		if err != nil {
			result.State = DetectionFailed
			result.Note = "temp tuple acquire: " + err.Error()
			return result
		}
		defer lease.Release() //nolint:errcheck // cleanup path

		mapping, err := mapper.Map(ctx, GatewayMapRequest{
			InternalIP:   source,
			InternalPort: lease.Actual.Port,
			Lease:        DetectionLease,
		})
		if err != nil {
			result.State = DetectionFailed
			result.Note = "map: " + err.Error()
			return result
		}
		// Cleanup: release the temp mapping right away.
		deleteErr := mapper.Delete(ctx, mapping)
		switch {
		case deleteErr == nil:
		default:
			// A failed temp delete is recorded but does not flip the
			// capability result; the lease bounds the damage.
			result.Note = "temp delete: " + deleteErr.Error()
		}

		result.State = DetectionPassed
		result.LayerSignature = mechanismSignature(mechanism, control)
		result.Candidate = mapping.External.String()
		result.Evidence = []LayerEvidence{mapping.Evidence(control)}
		return result
	}
}

// stunAttempt proves the TCP STUN observation capability.
func (d *Detector) stunAttempt(ctx context.Context) StrategyResult {
	result := StrategyResult{StartedAtUnix: time.Now().Unix()}
	defer func() { result.FinishedAtUnix = time.Now().Unix() }()

	if len(d.opts.StunServers) == 0 {
		result.State = DetectionFailed
		result.Note = "no STUN servers configured"
		return result
	}
	if d.opts.StunObserve == nil {
		result.State = DetectionFailed
		result.Note = "STUN observation unavailable in this build (no injected observer)"
		return result
	}
	for _, server := range d.opts.StunServers {
		address, err := parseStunTCPServer(server)
		if err != nil {
			continue
		}
		observed, err := d.opts.StunObserve(ctx, address, d.opts.AttemptTimeout)
		if err != nil {
			result.Note = strings.TrimSpace(result.Note + " " + server + ": " + err.Error())
			continue
		}
		result.State = DetectionPassed
		result.LayerSignature = "stun-tcp"
		result.Candidate = observed.String()
		result.Evidence = []LayerEvidence{{
			Kind:             LayerKindSTUN,
			ControlServer:    server,
			AssignedEndpoint: observed.String(),
			Scope:            scopeForAddr(observed.Addr()),
			Ownership:        OwnershipObservedOnly,
			ParentLayer:      -1,
			Note:             "temp observation; every Forward probes independently",
		}}
		return result
	}
	result.State = DetectionFailed
	if result.Note == "" {
		result.Note = "no usable STUN server"
	}
	return result
}

// tempSource picks the source address for temp gateway tuples: the
// default-route source when present, loopback for labs without one.
func (d *Detector) tempSource() netip.Addr {
	selection, _, err := Assess(d.opts.RouteTable)
	if err == nil && selection.Source.IsValid() {
		return selection.Source
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

// operationID generates a random hex operation ID for one attempt.
func (d *Detector) operationID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "det-unknown"
	}
	return hex.EncodeToString(b[:])
}

// mechanismSignature renders the layer signature for the profile.
func mechanismSignature(mechanism MappingLayerKind, control ControlServer) string {
	if mechanism == LayerUPnP && control.IGDv2 {
		return "upnp-igd:2"
	}
	return string(mechanism)
}

// scopeForAddr classifies one address for evidence records.
func scopeForAddr(addr netip.Addr) EndpointScope {
	if IsGlobalV4(addr) {
		return ScopeGlobalPublic
	}
	return ScopeFirstHop
}

// parseStunTCPServer parses the stun+tcp://host:port config form.
func parseStunTCPServer(server string) (netip.AddrPort, error) {
	rest, ok := strings.CutPrefix(server, "stun+tcp://")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("traversal: STUN server %q is not stun+tcp://", server)
	}
	addrPort, err := netip.ParseAddrPort(rest)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("traversal: STUN server %q: %w", server, err)
	}
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}

// replaceOrAppend replaces a strategy result in place or appends it.
func replaceOrAppend(results []StrategyResult, strategy protocol.Strategy, result StrategyResult) []StrategyResult {
	for i := range results {
		if results[i].Strategy == strategy {
			results[i] = result
			return results
		}
	}
	return append(results, result)
}

// sortedKeys is a helper for deterministic maps (kept for reviewer clarity;
// mechanism order above is explicit, so this only serves tests).
func sortedKeys(m map[MappingLayerKind]GatewayMapper) []MappingLayerKind {
	keys := make([]MappingLayerKind, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
