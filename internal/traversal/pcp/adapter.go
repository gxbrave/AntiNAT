// PCP adapter: bridges the wire client to the normalized
// traversal.GatewayMapper contract. Every transaction opens a short-lived
// UDP socket bound to the internal IP (PCP validates the request source
// address against the mapped client) and closes it after the exchange; the
// nonce in the mapping State is the only renewal/delete authority.
package pcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// AdapterOptions tune the adapter. Zero fields take client defaults.
type AdapterOptions struct {
	// Gateway is the PCP server endpoint; the default port is 5351. The
	// address is usually the IPv4 default gateway.
	Gateway netip.AddrPort
	// Timeout / MaxAttempts / Backoff pass through to the client.
	Timeout     time.Duration
	MaxAttempts int
	Backoff     time.Duration
}

// Adapter implements traversal.GatewayMapper over PCP.
type Adapter struct {
	gateway netip.AddrPort
	opts    ClientOptions
}

// NewAdapter builds the PCP adapter.
func NewAdapter(opts AdapterOptions) *Adapter {
	clientOpts := ClientOptions{
		Timeout:     opts.Timeout,
		MaxAttempts: opts.MaxAttempts,
		Backoff:     opts.Backoff,
	}
	gateway := opts.Gateway
	if !gateway.IsValid() || gateway.Port() == 0 {
		// Gateway address is required for real use; an invalid address
		// fails Discover rather than guessing the default gateway here.
		gateway = netip.AddrPort{}
	} else if gateway.Port() == 0 {
		gateway = netip.AddrPortFrom(gateway.Addr(), DefaultServerPort)
	}
	return &Adapter{gateway: gateway, opts: clientOpts}
}

// Mechanism reports the PCP layer kind.
func (a *Adapter) Mechanism() traversal.MappingLayerKind { return traversal.LayerPCP }

// Ownership reports STRONG_PROTOCOL_OWNERSHIP: the nonce is the authority.
func (a *Adapter) Ownership() traversal.OwnershipStrength { return traversal.OwnershipStrong }

// Capability reports the PCP port-control abilities.
func (a *Adapter) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(traversal.LayerPCP, false)
}

// Discover probes the gateway with ANNOUNCE (no side effects).
func (a *Adapter) Discover(ctx context.Context) (traversal.ControlServer, error) {
	if !a.gateway.IsValid() {
		return traversal.ControlServer{}, fmt.Errorf("pcp: adapter has no gateway endpoint")
	}
	conn, closeConn, err := a.dial()
	if err != nil {
		return traversal.ControlServer{}, err
	}
	defer closeConn()

	// ANNOUNCE carries the socket's actual source address: the gateway
	// validates the header against the datagram source, and the discovery
	// probe only proves reachability and epoch, not a mapping.
	local, ok := localAddrOf(conn)
	if !ok {
		return traversal.ControlServer{}, fmt.Errorf("pcp: control socket has no IPv4 source")
	}
	client := NewClient(conn, a.gateway, a.opts)
	if _, err := client.Announce(ctx, local); err != nil {
		return traversal.ControlServer{}, err
	}
	return traversal.ControlServer{
		Mechanism: traversal.LayerPCP,
		Address:   a.gateway.String(),
	}, nil
}

// Map acquires one TCP mapping.
func (a *Adapter) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	conn, closeConn, err := a.dialOn(req.InternalIP)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	result, err := client.Map(ctx, MapRequest{
		Protocol:              ProtoTCP,
		InternalAddress:       req.InternalIP,
		InternalPort:          req.InternalPort,
		SuggestedExternalPort: req.RequestedExternalPort,
		Lifetime:              req.Lease,
		PreferFailure:         req.StrictPort,
	})
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	return a.normalize(req, result), nil
}

// Renew extends the lease carrying the owning nonce.
func (a *Adapter) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	state, ok := mapping.State.(MapResult)
	if !ok {
		return traversal.GatewayMapping{}, fmt.Errorf("pcp: renewal state %T is not a PCP mapping", mapping.State)
	}
	conn, closeConn, err := a.dialOn(mapping.InternalIP)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	result, err := client.Renew(ctx, state, lifetime)
	if err != nil {
		return traversal.GatewayMapping{}, err
	}
	normalized := a.normalize(traversal.GatewayMapRequest{
		InternalIP:   mapping.InternalIP,
		InternalPort: mapping.InternalPort,
		Lease:        lifetime,
	}, result)
	return normalized, nil
}

// Delete releases the mapping carrying the owning nonce.
func (a *Adapter) Delete(ctx context.Context, mapping traversal.GatewayMapping) error {
	state, ok := mapping.State.(MapResult)
	if !ok {
		return fmt.Errorf("pcp: deletion state %T is not a PCP mapping", mapping.State)
	}
	conn, closeConn, err := a.dialOn(mapping.InternalIP)
	if err != nil {
		return err
	}
	defer closeConn()

	client := NewClient(conn, a.gateway, a.opts)
	_, err = client.Delete(ctx, state)
	return err
}

// normalize renders the normalized mapping from one client result.
func (a *Adapter) normalize(req traversal.GatewayMapRequest, result MapResult) traversal.GatewayMapping {
	external := netip.AddrPortFrom(result.AssignedExternalAddress, result.AssignedExternalPort)
	return traversal.GatewayMapping{
		Mechanism:    traversal.LayerPCP,
		Ownership:    traversal.OwnershipStrong,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     external,
		Lease:        result.Lifetime,
		Epoch:        result.Epoch,
		State:        result,
	}
}

// localAddrOf reads the socket's concrete IPv4 source address.
func localAddrOf(conn net.PacketConn) (netip.Addr, bool) {
	udp, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// dial opens a UDP socket bound to a wildcard address for ANNOUNCE.
func (a *Adapter) dial() (net.PacketConn, func(), error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("pcp: control socket: %w", err)
	}
	closeConn := func() { _ = conn.Close() }
	return conn, closeConn, nil
}

// dialOn opens a UDP socket bound to the internal IP so the gateway sees
// the mapped client address as the request source.
func (a *Adapter) dialOn(internalIP netip.Addr) (net.PacketConn, func(), error) {
	if !internalIP.IsValid() {
		return nil, nil, fmt.Errorf("pcp: mapping requires an internal IP")
	}
	conn, err := net.ListenPacket("udp4", internalIP.String()+":0")
	if err != nil {
		return nil, nil, fmt.Errorf("pcp: control socket on %s: %w", internalIP, err)
	}
	closeConn := func() { _ = conn.Close() }
	return conn, closeConn, nil
}
