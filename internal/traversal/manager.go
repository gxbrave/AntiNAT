// Per-Forward TCP traversal manager (Story 7): composes one Forward's
// acquisition — plan resolution, listener ownership, gateway mapping,
// optional same-tuple STUN observation — into structured evidence and a
// pipeline verdict, then keeps the mapping alive under the §3.5 renewal
// contract: renew near 50% of the granted lease with jitter, three
// consecutive failures surface the lost callback (publication goes stale
// per state-model §5), and a gateway reboot signal loses immediately.
// Release follows the mapping's ownership strength.
package traversal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ReleaseFunc releases one acquired listener.
type ReleaseFunc func() error

// ListenerSource acquires the production listener for one tuple. The
// composition root chooses the implementation: the plain PortRegistry for
// forwards without a same-tuple STUN observation, the stun shared-port
// registry when the upstream observation needs the same tuple (Linux gate).
type ListenerSource interface {
	Acquire(ctx context.Context, owner string, key TupleKey) (net.Listener, TupleKey, ReleaseFunc, error)
}

// PortRegistrySource adapts the agent-global PortRegistry.
type PortRegistrySource struct {
	Registry *PortRegistry
}

// Acquire implements ListenerSource.
func (s PortRegistrySource) Acquire(ctx context.Context, owner string, key TupleKey) (net.Listener, TupleKey, ReleaseFunc, error) {
	lease, err := s.Registry.Acquire(ctx, owner, key)
	if err != nil {
		return nil, TupleKey{}, nil, err
	}
	return lease.Listener, lease.Actual, lease.Release, nil
}

// ManagerOptions configure the manager.
type ManagerOptions struct {
	RouteTable RouteTable
	// Listeners acquires the production listener; nil uses the plain
	// PortRegistry.
	Listeners ListenerSource
	// Mappers are the available gateway mechanisms.
	Mappers map[MappingLayerKind]GatewayMapper
	// Journal persists mapping records; nil disables journaling (labs).
	Journal JournalStore
	// Clock is the renewal clock; default time.Now.
	Clock func() time.Time
	// OnMappingLost fires when the mapping degraded to LOST (three failed
	// renewals, gateway reboot or lease expiry margin). Publication state
	// must go stale; the manager never revives the old candidate.
	OnMappingLost func(forwardID string, reason string)
	// DefaultLease is the requested lease when the request omits one;
	// default 1h (§3.5 provisional freeze).
	DefaultLease time.Duration
	// StunObserve performs one transport-correct STUN observation from the
	// forward's own tuple (injected; the stun package depends on
	// traversal). Nil disables the upstream STUN layer.
	StunObserve func(ctx context.Context, server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error)
}

// Manager composes per-Forward TCP traversal acquisitions.
type Manager struct {
	opts      ManagerOptions
	listeners ListenerSource
}

// AcquireRequest parameterizes one acquisition.
type AcquireRequest struct {
	ForwardID string
	Owner     string
	Spec      protocol.ForwardSpec
	// Plan is the resolved strategy plan (detection profile or operator
	// selection resolved the mapping layer).
	Plan PlanRequest
	// Lease is the requested mapping lease; 0 uses the default.
	Lease time.Duration
	// RenewalInterval / RenewalJitterMax pace the renewal loop (the
	// production loop paces at ~50% of the granted lease; tests inject
	// faster pacing).
	RenewalInterval  time.Duration
	RenewalJitterMax time.Duration
	// StunServer is the stun+tcp:// endpoint for the optional same-tuple
	// upstream observation; empty disables the STUN layer.
	StunServer string
}

// Acquisition is one live Forward traversal binding.
type Acquisition struct {
	ForwardID string
	// Listener is the production listener; the caller wires the forward
	// data plane to it. Release closes it.
	Listener net.Listener
	Bind     TupleKey
	// Verdict classifies the composed layer chain.
	Verdict PipelineVerdict
	// Layers is the structured evidence in composition order.
	Layers []LayerEvidence
	// Mapping is the live gateway mapping; nil for direct/manual.
	Mapping *GatewayMapping
	// JournalID references the journal record (mapping_journal_ref).
	JournalID string

	manager   *Manager
	mapper    GatewayMapper
	releaseFn ReleaseFunc

	renewMu     sync.Mutex
	renewed     GatewayMapping
	renewStop   chan struct{}
	renewDone   chan struct{}
	renewOnce   sync.Once
	failedRenew int
	lostFired   bool
}

// NewManager builds a manager.
func NewManager(opts ManagerOptions) *Manager {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.DefaultLease <= 0 {
		opts.DefaultLease = time.Hour
	}
	listeners := opts.Listeners
	if listeners == nil {
		listeners = PortRegistrySource{Registry: NewPortRegistry()}
	}
	return &Manager{opts: opts, listeners: listeners}
}

// Acquire composes one Forward's traversal binding. The pipeline rules of
// EvaluateLayers gate the outcome: a strict final constraint violated by
// the observed layer fails the acquisition, and a FIRST_HOP candidate is
// returned with PublicCandidate=false so no publication can claim
// verification without the independent probe.
func (m *Manager) Acquire(ctx context.Context, req AcquireRequest) (*Acquisition, error) {
	if req.ForwardID == "" || req.Owner == "" {
		return nil, fmt.Errorf("traversal: acquisition requires forward and owner identities")
	}
	lease := req.Lease
	if lease <= 0 {
		lease = m.opts.DefaultLease
	}
	plan, err := PlanStrategy(req.Plan)
	if err != nil {
		return nil, err
	}

	acquisition := &Acquisition{
		ForwardID: req.ForwardID,
		manager:   m,
	}
	switch plan.Strategy {
	case protocol.StrategyDirectV4:
		if err := m.acquireDirect(ctx, req, acquisition); err != nil {
			return nil, err
		}
	case protocol.StrategyManualStaticV4:
		if err := m.acquireManual(ctx, req, plan, acquisition); err != nil {
			return nil, err
		}
	case protocol.StrategyExplicitGateway:
		if err := m.acquireGateway(ctx, req, plan, lease, acquisition); err != nil {
			m.releaseListenerQuietly(acquisition)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("traversal: manager does not acquire strategy %q (stun-only and auto resolve before acquisition)", plan.Strategy)
	}
	return acquisition, nil
}

// acquireDirect binds the global source; the candidate is the source plus
// the actual port.
func (m *Manager) acquireDirect(ctx context.Context, req AcquireRequest, acquisition *Acquisition) error {
	selection, capability, err := Assess(m.opts.RouteTable)
	if err != nil {
		if capability == "" {
			return fmt.Errorf("traversal: route assessment: %w", err)
		}
		return NewCapabilityError(capability, err)
	}
	if !selection.Global {
		return NewCapabilityError(CapabilityNoGlobalV4Source,
			fmt.Errorf("selected interface %s has no global IPv4 source", selection.Interface))
	}
	listener, actual, releaseFn, err := m.listeners.Acquire(ctx, req.Owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: selection.Source.String(), Port: req.Spec.RequestedLocalPort,
	})
	if err != nil {
		return fmt.Errorf("traversal: direct listener: %w", err)
	}
	acquisition.Listener = listener
	acquisition.Bind = actual
	acquisition.releaseFn = releaseFn
	candidate := netip.AddrPortFrom(selection.Source, actual.Port)
	acquisition.Layers = []LayerEvidence{{
		Kind:             LayerKindDirect,
		InternalEndpoint: candidate.String(),
		AssignedEndpoint: candidate.String(),
		Scope:            ScopeGlobalPublic,
		Ownership:        OwnershipNotApplicable,
		ParentLayer:      -1,
	}}
	verdict, err := EvaluateLayers(acquisition.Layers, PortPolicyAcceptAssigned)
	if err != nil {
		return err
	}
	acquisition.Verdict = verdict
	return nil
}

// acquireManual binds the listener and carries the operator endpoint as the
// candidate (USER_CONFIGURED_UNTESTED until the probe verifies it).
func (m *Manager) acquireManual(ctx context.Context, req AcquireRequest, plan StrategyPlan, acquisition *Acquisition) error {
	endpoint := req.Spec.ManualExpectedEndpoint
	if endpoint == "" {
		return ErrOperatorEndpointRequired
	}
	parsed, err := parseEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("traversal: manual endpoint: %w", err)
	}
	listener, actual, releaseFn, err := m.listeners.Acquire(ctx, req.Owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: "0.0.0.0", Port: req.Spec.RequestedLocalPort,
	})
	if err != nil {
		return fmt.Errorf("traversal: manual listener: %w", err)
	}
	acquisition.Listener = listener
	acquisition.Bind = actual
	acquisition.releaseFn = releaseFn
	acquisition.Layers = []LayerEvidence{{
		Kind:             LayerKindManual,
		InternalEndpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), actual.Port).String(),
		AssignedEndpoint: parsed.String(),
		Scope:            ScopeOperatorInput,
		Ownership:        OwnershipNotApplicable,
		ParentLayer:      -1,
	}}
	verdict, err := EvaluateLayers(acquisition.Layers, plan.FinalEndpointConstraint)
	if err != nil {
		return err
	}
	acquisition.Verdict = verdict
	return nil
}

// acquireGateway discovers the mechanism, binds the listener, maps the
// tuple, optionally observes the same tuple via STUN, and starts renewal.
func (m *Manager) acquireGateway(ctx context.Context, req AcquireRequest, plan StrategyPlan, lease time.Duration, acquisition *Acquisition) error {
	mapper, ok := m.opts.Mappers[plan.MappingLayer]
	if !ok {
		return fmt.Errorf("traversal: no %s mapper is available on this node", plan.MappingLayer)
	}
	control, err := mapper.Discover(ctx)
	if err != nil {
		return fmt.Errorf("traversal: %s discovery: %w", plan.MappingLayer, err)
	}

	source := m.sourceAddress()
	listener, actual, releaseFn, err := m.listeners.Acquire(ctx, req.Owner, TupleKey{
		Family: "ipv4", Protocol: "tcp", Address: source.String(), Port: req.Spec.RequestedLocalPort,
	})
	if err != nil {
		return fmt.Errorf("traversal: gateway listener: %w", err)
	}
	acquisition.Listener = listener
	acquisition.Bind = actual
	acquisition.releaseFn = releaseFn
	acquisition.mapper = mapper

	mapping, err := mapper.Map(ctx, GatewayMapRequest{
		InternalIP:            source,
		InternalPort:          actual.Port,
		RequestedExternalPort: req.Spec.RequestedPublicPort,
		Lease:                 lease,
		StrictPort:            plan.GatewayPortPolicy == PortPolicyStrict,
	})
	if err != nil {
		return fmt.Errorf("traversal: %s map: %w", plan.MappingLayer, err)
	}
	acquisition.Mapping = &mapping
	gatewayEvidence := mapping.Evidence(control)
	acquisition.Layers = []LayerEvidence{gatewayEvidence}

	// Upstream STUN layer on the same tuple (transport-correct): the
	// injected observer dials from the forward's own listener tuple. The
	// layer is optional: without a configured server or observer the
	// gateway evidence stands alone and the final endpoint is the gateway
	// assignment.
	if m.opts.StunObserve != nil && req.StunServer != "" {
		if server, parseErr := parseStunTCPServer(req.StunServer); parseErr == nil {
			if observed, observeErr := m.opts.StunObserve(ctx, server, 5*time.Second); observeErr == nil {
				acquisition.Layers = append(acquisition.Layers, LayerEvidence{
					Kind:             LayerKindSTUN,
					ControlServer:    req.StunServer,
					InternalEndpoint: netip.AddrPortFrom(source, actual.Port).String(),
					AssignedEndpoint: observed.String(),
					Scope:            scopeForAddr(observed.Addr()),
					Ownership:        OwnershipObservedOnly,
					ParentLayer:      0,
				})
			}
		}
	}

	verdict, err := EvaluateLayers(acquisition.Layers, plan.FinalEndpointConstraint)
	if err != nil {
		// Release the mapping before failing: ownership strength applies
		// on the failure path too.
		if deleteErr := mapper.Delete(ctx, mapping); deleteErr != nil {
			return errors.Join(err, deleteErr)
		}
		return err
	}
	acquisition.Verdict = verdict
	acquisition.JournalID = m.journalPut(req.ForwardID, acquisition.JournalID, mapping)
	m.startRenewal(req.ForwardID, acquisition, lease, req.RenewalInterval, req.RenewalJitterMax)
	return nil
}

// Release stops the renewal loop, deletes the mapping per its ownership
// strength and releases the listener. Best-effort failures surface as a
// joined error: the caller decides whether a gateway mapping leak is
// acceptable (weak/best-effort mechanisms) or fatal.
func (a *Acquisition) Release(ctx context.Context) error {
	a.stopRenewal()
	var errs []error
	if a.Mapping != nil && a.mapper != nil {
		if err := a.mapper.Delete(ctx, *a.Mapping); err != nil {
			errs = append(errs, err)
		}
	}
	if a.manager != nil && a.JournalID != "" && a.manager.opts.Journal != nil {
		if err := a.manager.opts.Journal.Delete(a.JournalID); err != nil {
			errs = append(errs, err)
		}
	}
	if a.releaseFn != nil {
		if err := a.releaseFn(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// Renewal loop (§3.5)
// ---------------------------------------------------------------------------

// startRenewal launches the renewal goroutine. The production pace renews
// near 50% of the granted lease with ±10% jitter; tests pace it faster via
// the request fields.
func (m *Manager) startRenewal(forwardID string, acquisition *Acquisition, lease time.Duration, requestedInterval, requestedJitter time.Duration) {
	interval := requestedInterval
	jitter := requestedJitter
	if interval <= 0 {
		interval = lease / 2
		jitter = lease / 10
	}
	acquisition.renewStop = make(chan struct{})
	acquisition.renewDone = make(chan struct{})
	go func() {
		defer close(acquisition.renewDone)
		timer := time.NewTimer(interval + jitterTime(jitter))
		defer timer.Stop()
		for {
			select {
			case <-acquisition.renewStop:
				return
			case <-timer.C:
			}
			m.renewOnce(forwardID, acquisition, lease, interval, jitter)
			timer.Reset(interval + jitterTime(jitter))
		}
	}()
}

// renewOnce performs one renewal attempt with the failure ladder: three
// consecutive failures fire the lost callback; a reboot signal fires
// immediately.
func (m *Manager) renewOnce(forwardID string, acquisition *Acquisition, lease time.Duration, interval time.Duration, jitter time.Duration) {
	acquisition.renewMu.Lock()
	defer acquisition.renewMu.Unlock()
	if acquisition.Mapping == nil || acquisition.mapper == nil {
		return
	}
	renewed, err := acquisition.mapper.Renew(context.Background(), *acquisition.Mapping, lease)
	if err != nil {
		acquisition.failedRenew++
		if acquisition.failedRenew >= 3 && !acquisition.lostFired {
			acquisition.lostFired = true
			m.fireLost(forwardID, "three consecutive renewals failed")
		}
		return
	}
	acquisition.failedRenew = 0
	if renewed.ServerRebooted && !acquisition.lostFired {
		acquisition.lostFired = true
		m.fireLost(forwardID, "gateway rebooted (epoch rollback)")
		return
	}
	acquisition.renewed = renewed
	acquisition.Mapping = &renewed
	acquisition.JournalID = m.journalPut(forwardID, acquisition.JournalID, renewed)
}

func (m *Manager) fireLost(forwardID string, reason string) {
	if m.opts.OnMappingLost != nil {
		m.opts.OnMappingLost(forwardID, reason)
	}
}

// journalPut persists one mapping record under a stable ID (first write
// derives it, renewals reuse it so the journal updates in place);
// journaling failures are non-fatal (the in-memory mapping stays
// authoritative). The record ID is returned for mapping_journal_ref.
func (m *Manager) journalPut(forwardID string, existingID string, mapping GatewayMapping) string {
	if m.opts.Journal == nil {
		return ""
	}
	recordID := existingID
	if recordID == "" {
		recordID = journalIDFor(forwardID, mapping)
	}
	record := JournalRecord{
		ID:              recordID,
		ForwardID:       forwardID,
		Mechanism:       mapping.Mechanism,
		Ownership:       mapping.Ownership,
		Protocol:        "tcp",
		InternalIP:      mapping.InternalIP.String(),
		InternalPort:    mapping.InternalPort,
		ExternalIP:      mapping.External.Addr().String(),
		ExternalPort:    mapping.External.Port(),
		LeaseExpiryUnix: m.opts.Clock().Add(mapping.Lease).Unix(),
		Epoch:           mapping.Epoch,
		Identity:        mapping.Identity,
		CreatedAtUnix:   m.opts.Clock().Unix(),
		UpdatedAtUnix:   m.opts.Clock().Unix(),
	}
	// Best effort: journaling must never break a live mapping.
	_ = m.opts.Journal.Put(record) //nolint:errcheck
	return recordID
}

// journalIDFor derives a stable journal record ID per forward.
func journalIDFor(forwardID string, mapping GatewayMapping) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return forwardID + "-" + string(mapping.Mechanism) + "-" + hexEncode(b[:])
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, hexDigits[v>>4], hexDigits[v&0x0f])
	}
	return string(out)
}

// sourceAddress resolves the acquisition source.
func (m *Manager) sourceAddress() netip.Addr {
	selection, _, err := Assess(m.opts.RouteTable)
	if err == nil && selection.Source.IsValid() {
		return selection.Source
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

// releaseListenerQuietly releases the listener on failed acquisition paths.
func (m *Manager) releaseListenerQuietly(acquisition *Acquisition) {
	if acquisition.releaseFn != nil {
		_ = acquisition.releaseFn() //nolint:errcheck
	}
}

// stopRenewal stops the renewal goroutine exactly once.
func (a *Acquisition) stopRenewal() {
	a.renewOnce.Do(func() {
		if a.renewStop != nil {
			close(a.renewStop)
		}
	})
	if a.renewDone != nil {
		<-a.renewDone
	}
}

// jitterTime returns a random duration in [0, max).
func jitterTime(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(max))
}
