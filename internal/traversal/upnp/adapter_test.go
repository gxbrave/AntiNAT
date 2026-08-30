package upnp

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// A1: the adapter advertises the honest mechanism identity and the
// best-effort ownership; the capability upgrades to v2 only after a
// discovery resolved an IGDv2 service.
func TestAdapterIdentityAndCapabilityUpgrade(t *testing.T) {
	adapter := NewAdapter(AdapterOptions{InterfaceIP: netip.MustParseAddr("127.0.0.1")})
	if adapter.Mechanism() != traversal.LayerUPnP {
		t.Fatalf("mechanism = %q, want upnp-igd", adapter.Mechanism())
	}
	if adapter.Ownership() != traversal.OwnershipBestEffort {
		t.Fatalf("ownership = %q, want BEST_EFFORT_QUERY_THEN_DELETE", adapter.Ownership())
	}
	if adapter.Capability().CanRequestExact {
		t.Fatal("unresolved adapter must report the weaker IGDv1 capability")
	}

	// Resolve an IGDv2 service so the capability table upgrades.
	service := Service{
		Type:       "urn:schemas-upnp-org:service:WANIPConnection:2",
		ControlURL: "http://127.0.0.1:1/ctl",
		IGDv2:      true,
	}
	adapter.resolve = func(ctx context.Context, a *Adapter) (Service, string, error) {
		return service, "uuid:lab-usn", nil
	}
	adapter.usn = "uuid:lab-usn"
	adapter.delegate = NewClient(http.DefaultClient, service, ClientOptions{})
	if !adapter.Capability().CanRequestExact {
		t.Fatal("IGDv2 capability must allow exact requests (AddAnyPortMapping)")
	}
}

// A2: Map before Discover fails instead of silently re-probing.
func TestAdapterRequiresDiscovery(t *testing.T) {
	adapter := NewAdapter(AdapterOptions{InterfaceIP: netip.MustParseAddr("127.0.0.1")})
	_, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP: netip.MustParseAddr("127.0.0.1"), InternalPort: 3111, Lease: time.Hour,
	})
	if err == nil {
		t.Fatal("Map before Discover must fail")
	}
}

// A3: the journal description carries the USN identity for stable ownership
// verification.
func TestAdapterMappingDescription(t *testing.T) {
	mapping := traversal.GatewayMapping{
		Mechanism:    traversal.LayerUPnP,
		Ownership:    traversal.OwnershipBestEffort,
		InternalIP:   netip.MustParseAddr("10.0.0.2"),
		InternalPort: 3111,
		External:     netip.MustParseAddrPort("203.0.113.7:43111"),
		Identity:     "uuid:lab-usn",
	}
	if mapping.Description() != "AntiNAT uuid:lab-usn" {
		t.Fatalf("description = %q", mapping.Description())
	}
	anonymous := mapping
	anonymous.Identity = ""
	if anonymous.Description() != "AntiNAT" {
		t.Fatalf("anonymous description = %q", anonymous.Description())
	}
}
