package contracts

// Frozen AntiNAT state and lifecycle model (docs/state-model.md).
//
// This reference pins:
//   - the orthogonal activation-state axes and their exact value enums;
//   - the AppliedForwardState record shape and its invariants;
//   - the durable control FSMs (outbox, inbox/operation, key rotation,
//     decommission, restore) with exact-predecessor transition rules.
//
// Every later implementation must accept exactly the same transitions and
// reject the same illegal transitions.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Orthogonal activation states
// ---------------------------------------------------------------------------

// stateAxis is one independent activation-state axis. The UI may compute
// aggregates, but an aggregate is never a protocol fact and cannot replace an
// axis value.
type stateAxis struct {
	name   string
	states map[string]bool
}

func axis(name string, states ...string) stateAxis {
	m := make(map[string]bool, len(states))
	for _, s := range states {
		m[s] = true
	}
	return stateAxis{name: name, states: m}
}

// activationAxes are the frozen orthogonal state axes (v0.8 §2.1).
var activationAxes = []stateAxis{
	axis("control_state", "ONLINE", "OFFLINE"),
	axis("listener_state", "STOPPED", "STARTING", "READY", "ERROR"),
	axis("mapping_state", "NOT_REQUIRED", "ACQUIRING", "FIRST_HOP_MAPPED", "PUBLIC_CANDIDATE", "LOST", "ERROR"),
	axis("keepalive_state", "NOT_REQUIRED", "HEALTHY", "DEGRADED", "LOST"),
	axis("wan_reachability_state", "NOT_TESTED", "PROBING", "OPEN_FROM_VANTAGE", "REJECTED", "TIMEOUT", "NO_INDEPENDENT_VANTAGE", "PROBE_INFRA_UNAVAILABLE", "UNKNOWN"),
	axis("return_path_state", "NOT_TESTED", "VERIFIED", "FAILED", "UNKNOWN"),
	axis("target_health_state", "PASS", "FAIL", "SKIPPED", "UNSUPPORTED", "UNKNOWN"),
	axis("publication_state", "NONE", "PUBLISHED_VERIFIED", "PUBLISHED_UNVERIFIED", "STALE", "UNPUBLISHED"),
	axis("data_plane_state", "STOPPED", "READY", "DEGRADED", "ERROR"),
}

// validAxisState reports whether value is a legal value of the named axis.
func validAxisState(axisName, value string) bool {
	for _, a := range activationAxes {
		if a.name == axisName {
			return a.states[value]
		}
	}
	return false
}

// validActivationSnapshot validates a complete orthogonal snapshot: every
// field must be a known axis with a legal value, and no extra fields.
func validActivationSnapshot(s map[string]string) error {
	if len(s) != len(activationAxes) {
		return fmt.Errorf("activation snapshot has %d axes, want %d", len(s), len(activationAxes))
	}
	for _, a := range activationAxes {
		v, ok := s[a.name]
		if !ok {
			return fmt.Errorf("activation snapshot missing axis %q", a.name)
		}
		if !a.states[v] {
			return fmt.Errorf("axis %q has illegal value %q", a.name, v)
		}
	}
	return nil
}

// publicationInvariants enforces the frozen publication truth rules.
func publicationInvariants(pubState, wanReach, returnPath string) error {
	switch pubState {
	case "PUBLISHED_VERIFIED":
		if wanReach != "OPEN_FROM_VANTAGE" {
			return errors.New("PUBLISHED_VERIFIED requires wan_reachability_state=OPEN_FROM_VANTAGE")
		}
		if returnPath != "VERIFIED" {
			return errors.New("PUBLISHED_VERIFIED requires return_path_state=VERIFIED")
		}
	case "PUBLISHED_UNVERIFIED":
		if wanReach == "OPEN_FROM_VANTAGE" {
			return errors.New("PUBLISHED_UNVERIFIED must not claim OPEN_FROM_VANTAGE")
		}
	case "FIRST_HOP_MAPPED":
		// mapping axis is separate; this switch is for publication only
	}
	return nil
}

// ---------------------------------------------------------------------------
// AppliedForwardState
// ---------------------------------------------------------------------------

// appliedForwardState is the frozen durable record the Agent persists as LKG
// for a Forward. It never persists a directly-restorable verified health.
type appliedForwardState struct {
	ForwardID             string `json:"forward_id"`
	SpecRevision          uint64 `json:"spec_revision"`
	DesiredRevision       uint64 `json:"desired_revision"`
	ActualBindHost        string `json:"actual_bind_host"`
	ActualBindPort        uint16 `json:"actual_bind_port"`
	AssignedGatewayPort   uint16 `json:"assigned_gateway_port,omitempty"`
	PublicPort            uint16 `json:"public_port,omitempty"`
	Strategy              string `json:"strategy"`
	LayerVersion          uint64 `json:"layer_version"`
	ActivationRecovery    string `json:"activation_recovery_descriptor"`
	MappingJournalRef     string `json:"mapping_journal_ref,omitempty"`
	HookDefinitionVersion uint64 `json:"hook_definition_version,omitempty"`
	HookSecretVersion     uint64 `json:"hook_secret_version,omitempty"`
	AppliedAtUnix         int64  `json:"applied_at_unix"`
}

var validStrategies = map[string]bool{
	"direct-v4":        true,
	"manual-static-v4": true,
	"explicit-gateway": true,
	"stun-only":        true,
	"auto":             true,
}

func validAppliedForwardState(a appliedForwardState) error {
	if a.ForwardID == "" {
		return errors.New("forward_id must be non-empty")
	}
	if a.DesiredRevision < a.SpecRevision {
		return errors.New("desired_revision must be >= spec_revision")
	}
	if a.ActualBindHost == "" || a.ActualBindPort == 0 {
		return errors.New("actual bind tuple must be concrete")
	}
	if !validStrategies[a.Strategy] {
		return fmt.Errorf("unknown strategy %q", a.Strategy)
	}
	if a.AppliedAtUnix <= 0 {
		return errors.New("applied_at_unix must be set")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Durable control FSMs
// ---------------------------------------------------------------------------

// transitionTable maps (from, to) legal transitions per FSM.
type transitionTable map[[2]string]bool

func pair(from, to string) [2]string { return [2]string{from, to} }

// frozenFSMs holds the exact-predecessor transition tables. A transition is
// legal only if the source state is the exact predecessor (single-step).
var frozenFSMs = map[string]transitionTable{
	"outbox": {
		pair("PENDING", "CLAIMED"):          true,
		pair("CLAIMED", "SENT"):             true,
		pair("SENT", "SEMANTIC_ACKED"):      true,
		pair("SEMANTIC_ACKED", "RECEIPTED"): true,
		pair("RECEIPTED", "GC"):             true,
	},
	"inbox": {
		pair("RECEIVED", "INTENT_PERSISTED"): true,
		pair("INTENT_PERSISTED", "APPLYING"): true,
		pair("APPLYING", "APPLIED"):          true,
		pair("APPLYING", "NACKED"):           true,
	},
	"key_rotation": {
		pair("PREPARED", "ANNOUNCED"): true,
		pair("ANNOUNCED", "ACKED"):    true,
		pair("ACKED", "ACTIVE"):       true,
		pair("ACTIVE", "RETIRED"):     true,
	},
	"decommission": {
		pair("ACTIVE", "DECOMMISSIONING"):         true,
		pair("DECOMMISSIONING", "DECOMMISSIONED"): true,
		pair("DECOMMISSIONED", "CLEANUP_ONLY"):    true,
	},
	"restore": {
		pair("RESTORED", "RECOVERY_QUARANTINE"):    true,
		pair("RECOVERY_QUARANTINE", "RECONCILING"): true,
		pair("RECONCILING", "AUTHORIZED"):          true,
	},
}

var frozenFSMStates = map[string]map[string]bool{
	"outbox":       stateSet("PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED", "RECEIPTED", "GC"),
	"inbox":        stateSet("RECEIVED", "INTENT_PERSISTED", "APPLYING", "APPLIED", "NACKED"),
	"key_rotation": stateSet("PREPARED", "ANNOUNCED", "ACKED", "ACTIVE", "RETIRED"),
	"decommission": stateSet("ACTIVE", "DECOMMISSIONING", "DECOMMISSIONED", "CLEANUP_ONLY"),
	"restore":      stateSet("RESTORED", "RECOVERY_QUARANTINE", "RECONCILING", "AUTHORIZED"),
}

func stateSet(states ...string) map[string]bool {
	m := make(map[string]bool, len(states))
	for _, s := range states {
		m[s] = true
	}
	return m
}

// validateFSMTransition returns nil iff the transition is single-step legal.
func validateFSMTransition(fsm, from, to string) error {
	table, ok := frozenFSMs[fsm]
	if !ok {
		return fmt.Errorf("unknown FSM %q", fsm)
	}
	if !frozenFSMStates[fsm][from] {
		return fmt.Errorf("FSM %q has no state %q", fsm, from)
	}
	if !frozenFSMStates[fsm][to] {
		return fmt.Errorf("FSM %q has no state %q", fsm, to)
	}
	if !table[pair(from, to)] {
		return fmt.Errorf("illegal transition %s -> %s in FSM %q", from, to, fsm)
	}
	return nil
}

// parseStateFixtureJSON is a strict parser for state-model fixtures (used by
// both the golden validator and the generator).
func parseStateFixtureJSON(raw []byte, out *stateFixture) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}
