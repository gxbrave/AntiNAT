package pcp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/traversal"
)

func netipMustParse(text string) netip.Addr { return netip.MustParseAddr(text) }

func controlServerFor(address string) traversal.ControlServer {
	return traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: address}
}

// Story 5 RED: the PCP adapter bridges the wire client to the normalized
// traversal.GatewayMapper contract with strong ownership evidence.

// A1: the adapter advertises the honest mechanism identity and capability.
func TestAdapterIdentity(t *testing.T) {
	adapter := NewAdapter(AdapterOptions{})
	if adapter.Mechanism() != traversal.LayerPCP {
		t.Fatalf("mechanism = %q, want pcp", adapter.Mechanism())
	}
	if adapter.Ownership() != traversal.OwnershipStrong {
		t.Fatalf("ownership = %q, want STRONG_PROTOCOL_OWNERSHIP", adapter.Ownership())
	}
	capability := adapter.Capability()
	if !capability.CanRequestExact || !capability.CanRetryCandidate {
		t.Fatalf("PCP capability = %+v, want exact+retry", capability)
	}
}

// A2: Discover probes the gateway with ANNOUNCE and reports the control
// server with the observed epoch.
func TestAdapterDiscover(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if request[1]&0x7f == OpCodeAnnounce {
			response := make([]byte, 28)
			response[0] = Version
			response[1] = ResponseFlag | OpCodeAnnounce
			response[3] = ResultSuccess
			putUint32(response[8:12], 0x0f00)
			copy(response[12:28], request[12:28])
			return response
		}
		return successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	control, err := adapter.Discover(t.Context())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if control.Mechanism != traversal.LayerPCP {
		t.Fatalf("mechanism = %q, want pcp", control.Mechanism)
	}
	if control.Address != server.peer.String() {
		t.Fatalf("control address = %q, want %q", control.Address, server.peer.String())
	}
}

// A3: Map returns the normalized mapping with the strong-ownership nonce in
// State, and the non-global assigned endpoint classifies as FIRST_HOP
// evidence — never a public candidate.
func TestAdapterMapAndEvidence(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		response := successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
		// A real gateway assigns the external port itself.
		putUint16(response[28+18:28+20], 43111)
		return response
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP:   netipMustParse("127.0.0.1"),
		InternalPort: 3111,
		Lease:        time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapping.Mechanism != traversal.LayerPCP || mapping.Ownership != traversal.OwnershipStrong {
		t.Fatalf("mapping identity = %s/%s", mapping.Mechanism, mapping.Ownership)
	}
	if mapping.External.Port() == 0 {
		t.Fatal("normalized mapping must carry the assigned external port")
	}
	if _, ok := mapping.State.(MapResult); !ok {
		t.Fatalf("State = %T, want the PCP MapResult renewal state", mapping.State)
	}

	evidence := mapping.Evidence(controlServerFor(server.peer.String()))
	verdict, err := traversal.EvaluateLayers([]traversal.LayerEvidence{evidence}, traversal.PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("EvaluateLayers: %v", err)
	}
	if verdict.PublicCandidate {
		t.Fatal("a TEST-NET assigned endpoint must never be a public candidate")
	}
	if verdict.Scope != traversal.ScopeFirstHop {
		t.Fatalf("scope = %q, want FIRST_HOP", verdict.Scope)
	}
}

// A4: Delete passes the owning state back through the adapter.
func TestAdapterDeleteRoundTrip(t *testing.T) {
	var mu sync.Mutex
	deleteSeen := false
	var seenNonce [12]byte
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			return successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
		}
		lifetime := readUint32(request[4:8])
		if lifetime != 0 {
			server.errorf("delete lifetime = %d, want 0", lifetime)
		}
		mu.Lock()
		copy(seenNonce[:], request[28:40])
		deleteSeen = true
		mu.Unlock()
		response := successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
		putUint32(response[4:8], 0)
		return response
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP:   netipMustParse("127.0.0.1"),
		InternalPort: 3111,
		Lease:        time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if err := adapter.Delete(t.Context(), mapping); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	state := mapping.State.(MapResult)
	mu.Lock()
	seen, nonce := deleteSeen, seenNonce
	mu.Unlock()
	if !seen || nonce != state.Nonce {
		t.Fatalf("delete must carry the owning nonce (seen=%v nonce=%v)", deleteSeen, seenNonce)
	}
}
