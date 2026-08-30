// NAT-PMP adapter: bridges the wire client to the normalized
// traversal.GatewayMapper contract with WEAK_LEASE_OWNERSHIP. Ownership is
// weak because NAT-PMP carries no client identity: only the lease and the
// exact internal tuple bind the mapping. Discovery is the public-address
// probe; the response's assigned port is always authoritative.
package natpmp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// AdapterOptions tune the adapter.
type AdapterOptions struct {
	// Gateway is the NAT-PMP server endpoint (usually the IPv4 default
	// gateway; the registered port is 5351).
	Gateway netip.AddrPort
	// Timeout / MaxAttempts / Backoff pass through to the client.
	Timeout     time.Duration
	MaxAttempts int
	Backoff     time.Duration
}

// Adapter implements traversal.GatewayMapper over NAT-PMP.
type Adapter struct {
	gateway netip.AddrPort
	opts    ClientOptions
}

// NewAdapter builds the NAT-PMP adapter.
func NewAdapter(opts AdapterOptions) *Adapter {
	gateway := opts.Gateway
	if gateway.IsValid() && gateway.Port() == 0 {
		gateway = netip.AddrPortFrom(gateway.Addr(), DefaultServerPort)
	}
	return &Adapter{
		gateway: gateway,
		opts: ClientOptions{
			Timeout:     opts.Timeout,
			MaxAttempts: opts.MaxAttempts,
			Backoff:     opts.Backoff,
		},
	}
}

// Mechanism reports the NAT-PMP layer kind.
func (a *Adapter) Mechanism() traversal.MappingLayerKind { return traversal.LayerNATPMP }

// Ownership reports WEAK_LEASE_OWNERSHIP (v0.8 §3.4): no protocol identity,
// short leases, active delete only for the exact owned tuple.
func (a *Adapter) Ownership() traversal.OwnershipStrength { return traversal.OwnershipWeakLease }

// Capability reports the NAT-PMP port-control abilities: the requested port
// is a suggestion, the response decides.
func (a *Adapter) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(traversal.LayerNATPMP, false)
}

// Discover probes the gateway with the public-address request.
func (a *Adapter) Discover(ctx context.Context) (traversal.ControlServer, error) {
	if !a.gateway.IsValid() {
		return traversal.ControlServer{}, fmt.Errorf("natpmp: adapter has no gateway endpoint")
	}
	conn, closeConn, err := a.dial()
	if err != nil {
		return traversal.ControlServer{}, err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	if _, _, err := client.PublicAddress(ctx); err != nil {
		return traversal.ControlServer{}, err
	}
	return traversal.ControlServer{
		Mechanism: traversal.LayerNATPMP,
		Address:   a.gateway.String(),
	}, nil
}

// Map acquires one TCP mapping; the assigned port is authoritative.
func (a *Adapter) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	if req.StrictPort {
		return traversal.GatewayMapping{}, traversal.ErrLayerCannotRequestExact
	}
	conn, closeConn, err := a.dial()
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	result, err := client.Map(ctx, MapRequest{
		Protocol:              ProtocolTCP,
		InternalPort:          req.InternalPort,
		RequestedExternalPort: req.RequestedExternalPort,
		Lifetime:              req.Lease,
	})
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	return a.normalize(req, result), nil
}

// Renew extends the lease for the exact owned tuple.
func (a *Adapter) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	conn, closeConn, err := a.dial()
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	result, err := client.Renew(ctx, MapResult{
		Protocol:             ProtocolTCP,
		InternalPort:         mapping.InternalPort,
		AssignedExternalPort: mapping.External.Port(),
	}, lifetime)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	return a.normalize(traversal.GatewayMapRequest{
		InternalIP:   mapping.InternalIP,
		InternalPort: mapping.InternalPort,
	}, result), nil
}

// Delete releases the exact owned tuple (lifetime 0). Zero internal ports
// are refused client-side by the client; the adapter forwards the refusal.
func (a *Adapter) Delete(ctx context.Context, mapping traversal.GatewayMapping) error {
	conn, closeConn, err := a.dial()
	if err != nil {
		return err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	_, err = client.Delete(ctx, MapResult{
		Protocol:             ProtocolTCP,
		InternalPort:         mapping.InternalPort,
		AssignedExternalPort: mapping.External.Port(),
	})
	return err
}

// normalize renders the normalized mapping from one client result.
func (a *Adapter) normalize(req traversal.GatewayMapRequest, result MapResult) traversal.GatewayMapping {
	return traversal.GatewayMapping{
		Mechanism:      traversal.LayerNATPMP,
		Ownership:      traversal.OwnershipWeakLease,
		InternalIP:     req.InternalIP,
		InternalPort:   result.InternalPort,
		External:       netip.AddrPortFrom(a.gateway.Addr(), result.AssignedExternalPort),
		Lease:          result.Lifetime,
		Epoch:          result.Epoch,
		ServerRebooted: result.ServerRebooted,
		State:          result,
	}
}

// dial opens a UDP socket for the next transaction. NAT-PMP requests carry
// no client address field (the datagram source is the identity), so a
// wildcard bind is correct.
func (a *Adapter) dial() (net.PacketConn, func(), error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("natpmp: control socket: %w", err)
	}
	closeConn := func() { _ = conn.Close() }
	return conn, closeConn, nil
}
