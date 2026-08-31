// Forward strategy translation (P12W Stories 2-5): turns the frozen
// ForwardSpec strategy (+ the node's cached detection profile + the
// configured STUN servers) into the concrete traversal.PlanRequest the
// Manager acquires with. `auto` is resolved to a concrete strategy BEFORE
// acquisition (the Manager refuses auto/stun-only directly). The STUN-only
// composer is the agent-side acquisition for a forward that observes its
// endpoint through same-tuple STUN without any gateway control.
package agent

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// Strategy translation errors surfaced as apply failures (truthful, not an
// Applied state).
var (
	// errExplicitGatewayNeedsLayer refuses explicit-gateway without a
	// resolved gateway mechanism in the detection profile.
	errNoGatewayLayerInProfile = errors.New("agent: explicit-gateway requires a resolved mapping layer in the detection profile")
	// errNoStunServer refuses stun-only without a configured STUN server.
	errNoStunServer = errors.New("agent: stun-only requires a configured STUN server")
	// errAutoNoPassingDefault refuses auto when the detection profile has no
	// PASSED default strategy (stale or absent capability is never reused).
	errAutoNoPassingDefault = errors.New("agent: auto requires a detection profile default strategy that PASSED")
)

// planFor translates one ForwardSpec into the resolved traversal PlanRequest.
// strategy must already be concrete (auto is resolved by resolveAutoStrategy
// before this prefers to plan concrete routes). The profile is the cached
// detection profile used to resolve the explicit-gateway mechanism; direct,
// manual and stun-only carry no mapping layer.
//
// D4 (binding): a pinned public port (RequestedPublicPort != 0) is a strict
// request only for a mechanism that can request exact ports (PCP, UPnP
// IGDv2); NAT-PMP and IGDv1 treat it as a suggestion
// (PortPolicyAcceptAny) — the honest per-mechanism capability.
func planFor(spec protocol.ForwardSpec, profile traversal.Profile, stunServers []string) (traversal.PlanRequest, error) {
	switch spec.Strategy {
	case protocol.StrategyDirectV4:
		return traversal.PlanRequest{Strategy: protocol.StrategyDirectV4}, nil
	case protocol.StrategyManualStaticV4:
		if spec.ManualExpectedEndpoint == "" {
			return traversal.PlanRequest{}, traversal.ErrOperatorEndpointRequired
		}
		return traversal.PlanRequest{
			Strategy:               protocol.StrategyManualStaticV4,
			ManualExpectedEndpoint: spec.ManualExpectedEndpoint,
		}, nil
	case protocol.StrategyExplicitGateway:
		layer, igdV2, ok := explicitGatewayLayer(profile)
		if !ok {
			return traversal.PlanRequest{}, errNoGatewayLayerInProfile
		}
		plan := traversal.PlanRequest{
			Strategy:                protocol.StrategyExplicitGateway,
			MappingLayer:            layer,
			IGDv2:                   igdV2,
			GatewayPortPolicy:       traversal.PortPolicyAcceptAny,
			FinalEndpointConstraint: traversal.PortPolicyAcceptAssigned,
		}
		if spec.RequestedPublicPort != 0 && traversal.PortControlCapabilityFor(layer, igdV2).CanRequestExact {
			plan.GatewayPortPolicy = traversal.PortPolicyStrict
			plan.FinalEndpointConstraint = traversal.PortPolicyStrict
		}
		return plan, nil
	case protocol.StrategyStunOnly:
		if len(stunServers) == 0 {
			return traversal.PlanRequest{}, errNoStunServer
		}
		return traversal.PlanRequest{Strategy: protocol.StrategyStunOnly}, nil
	case protocol.StrategyAuto:
		return traversal.PlanRequest{Strategy: protocol.StrategyAuto}, nil
	default:
		return traversal.PlanRequest{}, fmt.Errorf("agent: unknown strategy %q", spec.Strategy)
	}
}

// explicitGatewayLayer resolves the profile's passing explicit-gateway result
// into the concrete mapping mechanism and UPnP IGD version. A non-PASSED or
// absent result means no mechanism is available on this node.
func explicitGatewayLayer(profile traversal.Profile) (traversal.MappingLayerKind, bool, bool) {
	result, ok := profile.ResultFor(protocol.StrategyExplicitGateway)
	if !ok || result.State != traversal.DetectionPassed {
		return "", false, false
	}
	switch {
	case strings.HasPrefix(result.LayerSignature, "upnp-igd"):
		return traversal.LayerUPnP, result.LayerSignature == "upnp-igd:2", true
	case result.LayerSignature == "pcp":
		return traversal.LayerPCP, false, true
	case result.LayerSignature == "nat-pmp":
		return traversal.LayerNATPMP, false, true
	default:
		return "", false, false
	}
}

// resolveAutoStrategy resolves one auto Forward to its concrete strategy.
// UDP auto stays direct-v4 (P13 owns the UDP dataplane; detection is
// deferred for UDP). TCP auto requires the cached profile's default strategy
// to be PASSED: a stale or absent profile fails rather than silently reusing
// an old capability (Story 5).
func resolveAutoStrategy(spec protocol.ForwardSpec, profile traversal.Profile, haveProfile bool, order []protocol.Strategy) (protocol.Strategy, error) {
	if spec.Protocol == protocol.ProtocolUDP {
		return protocol.StrategyDirectV4, nil
	}
	if !haveProfile || profile.DefaultStrategy == "" {
		return "", errAutoNoPassingDefault
	}
	result, ok := profile.ResultFor(profile.DefaultStrategy)
	if !ok || result.State != traversal.DetectionPassed {
		return "", errAutoNoPassingDefault
	}
	return profile.DefaultStrategy, nil
}

// forwardRoute is the resolved acquisition direction for one spec: which
// manager (or the agent-side STUN-only composer) acquires the listener.
type forwardRoute struct {
	plan traversal.PlanRequest
	// manager is the traversal.Manager that acquires the listener; nil for
	// stun-only (the composer acquires directly through the shared-port seam).
	manager *traversal.Manager
	// isGateway selects the gateway manager path (shared-port listeners).
	isGateway bool
	// stunOnly routes through the agent-side STUN-only composer.
	stunOnly bool
}

// resolveForwardRoute translates one ForwardSpec into its acquisition route.
// Auto is resolved to a concrete strategy first (UDP auto → direct-v4).
func (d *dataPlane) resolveForwardRoute(spec protocol.ForwardSpec) (forwardRoute, error) {
	strategy := spec.Strategy
	if strategy == protocol.StrategyAuto {
		profile, haveProfile, err := d.loadProfile()
		if err != nil {
			return forwardRoute{}, err
		}
		if err := d.validateAutoProfile(profile, haveProfile); err != nil {
			return forwardRoute{}, err
		}
		resolved, err := resolveAutoStrategy(spec, profile, haveProfile, d.cfg.AutoOrder)
		if err != nil {
			return forwardRoute{}, err
		}
		strategy = resolved
		// planFor reads spec.Strategy; route the resolved concrete strategy so
		// the acquisition plan never carries "auto" into the Manager.
		spec.Strategy = resolved
	}
	// UDP is always direct-v4 (P13 UDP stays on the direct path; the Manager
	// is TCP-listener based).
	if spec.Protocol == protocol.ProtocolUDP && strategy != protocol.StrategyDirectV4 {
		strategy = protocol.StrategyDirectV4
		spec.Strategy = protocol.StrategyDirectV4
	}
	switch strategy {
	case protocol.StrategyDirectV4:
		return forwardRoute{plan: traversal.PlanRequest{Strategy: protocol.StrategyDirectV4}, manager: d.cfg.PlainManager}, nil
	case protocol.StrategyManualStaticV4:
		plan, err := planFor(spec, traversal.Profile{}, nil)
		if err != nil {
			return forwardRoute{}, err
		}
		return forwardRoute{plan: plan, manager: d.cfg.PlainManager}, nil
	case protocol.StrategyExplicitGateway:
		profile, haveProfile, err := d.loadProfile()
		if err != nil {
			return forwardRoute{}, err
		}
		if !haveProfile {
			return forwardRoute{}, errNoGatewayLayerInProfile
		}
		plan, err := planFor(spec, profile, d.cfg.StunServers)
		if err != nil {
			return forwardRoute{}, err
		}
		return forwardRoute{plan: plan, manager: d.cfg.GatewayManager, isGateway: true}, nil
	case protocol.StrategyStunOnly:
		plan, err := planFor(spec, traversal.Profile{}, d.cfg.StunServers)
		if err != nil {
			return forwardRoute{}, err
		}
		return forwardRoute{plan: plan, stunOnly: true}, nil
	default:
		return forwardRoute{}, fmt.Errorf("agent: unknown strategy %q", strategy)
	}
}

// loadProfile reads the cached detection profile.
func (d *dataPlane) loadProfile() (traversal.Profile, bool, error) {
	if d.cfg.ProfileStore == nil {
		return traversal.Profile{}, false, nil
	}
	return d.cfg.ProfileStore.Load()
}

// profileMaxAge is how old a detection profile may be before an auto apply
// refuses to reuse it (a node's capabilities can change; a stale profile is
// never silently treated as current).
const profileMaxAge = 24 * time.Hour

// validateAutoProfile applies the Story 5 staleness gate: an auto forward
// refuses a cached profile that no longer describes the node (fingerprint
// changed or older than profileMaxAge). UDP auto never looks at the profile.
func (d *dataPlane) validateAutoProfile(profile traversal.Profile, haveProfile bool) error {
	if !haveProfile || profile.Fingerprint == "" {
		return nil // absent profile handled by resolveAutoStrategy
	}
	fingerprint, err := traversal.Fingerprint(d.cfg.RouteTable)
	if err != nil {
		return fmt.Errorf("agent: detection fingerprint: %w", err)
	}
	if stale, reason := profile.IsStale(fingerprint, profileMaxAge, d.cfg.Clock()); stale {
		return fmt.Errorf("agent: detection profile is stale (%s)", reason)
	}
	return nil
}

// firstStunServer returns the primary configured STUN endpoint, or "" when
// none are configured.
func firstStunServer(servers []string) string {
	if len(servers) == 0 {
		return ""
	}
	return servers[0]
}
