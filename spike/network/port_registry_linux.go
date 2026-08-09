//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

var (
	ErrTupleOverlap = errors.New("port registry tuple overlaps an existing lease")
	ErrStaleLease   = errors.New("port registry lease is stale")
)

type registryKey struct {
	address string
	port    int
}

type registryEntry struct {
	owner      string
	generation uint64
	lease      *TCPLease
}

// PortRegistry is a spike for socket-owning acquisition, not a production API.
type PortRegistry struct {
	mu         sync.Mutex
	entries    map[registryKey]registryEntry
	generation uint64
}

// TCPLease owns the actual listener returned by the OS.
type TCPLease struct {
	Listener   *net.TCPListener
	registry   *PortRegistry
	key        registryKey
	owner      string
	generation uint64
}

func NewPortRegistry() *PortRegistry {
	return &PortRegistry{entries: make(map[registryKey]registryEntry)}
}

// AcquireTCP performs overlap validation, bind, actual-port discovery, and
// entry publication while holding one registry critical section.
func (registry *PortRegistry) AcquireTCP(ctx context.Context, owner string, requested *net.TCPAddr) (*TCPLease, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if owner == "" {
		return nil, errors.New("owner is required")
	}
	requestedKey := keyForTCPAddr(requested)
	if requested.Port != 0 && registry.overlaps(requestedKey) {
		return nil, ErrTupleOverlap
	}

	listenConfig := net.ListenConfig{}
	socket, err := listenConfig.Listen(ctx, "tcp4", requested.String())
	if err != nil {
		return nil, err
	}
	listener, ok := socket.(*net.TCPListener)
	if !ok {
		socket.Close()
		return nil, fmt.Errorf("tcp4 listen returned %T", socket)
	}
	actualKey := keyForTCPAddr(listener.Addr().(*net.TCPAddr))
	if registry.overlaps(actualKey) {
		listener.Close()
		return nil, ErrTupleOverlap
	}

	registry.generation++
	lease := &TCPLease{
		Listener:   listener,
		registry:   registry,
		key:        actualKey,
		owner:      owner,
		generation: registry.generation,
	}
	registry.entries[actualKey] = registryEntry{owner: owner, generation: lease.generation, lease: lease}
	return lease, nil
}

func keyForTCPAddr(address *net.TCPAddr) registryKey {
	ip := address.IP.String()
	if address.IP == nil || address.IP.IsUnspecified() {
		ip = "0.0.0.0"
	}
	return registryKey{address: ip, port: address.Port}
}

func (registry *PortRegistry) overlaps(candidate registryKey) bool {
	for existing := range registry.entries {
		if existing.port != candidate.port {
			continue
		}
		if existing.address == "0.0.0.0" || candidate.address == "0.0.0.0" || existing.address == candidate.address {
			return true
		}
	}
	return false
}

func (registry *PortRegistry) Len() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.entries)
}

// Release closes only the entry whose owner and generation still match.
func (lease *TCPLease) Release() error {
	registry := lease.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry, ok := registry.entries[lease.key]
	if !ok || entry.owner != lease.owner || entry.generation != lease.generation || entry.lease != lease {
		return ErrStaleLease
	}
	delete(registry.entries, lease.key)
	return lease.Listener.Close()
}
