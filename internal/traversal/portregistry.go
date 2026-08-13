// Socket-owning PortRegistry (v0.8 §4.1): one Agent-global registry keyed by
// (family, protocol, concrete source address, local port) with
// wildcard/specific overlap checks. Acquire creates, binds, and listens the
// actual socket inside one registry critical section — never
// bind-then-close-then-rebind — and port 0 is resolved to the OS-assigned
// actual port before the entry is published. A stale release carries the
// owner generation and can never close a new owner's socket. The OS
// single-instance lock is the process-level complement (one Agent instance,
// stop-old-before-start-new).
package traversal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
)

// Port registry and instance-lock sentinel errors.
var (
	ErrTupleOverlap     = errors.New("traversal: port registry tuple overlaps an existing lease")
	ErrStaleLease       = errors.New("traversal: port registry lease is stale")
	ErrUnsupportedTuple = errors.New("traversal: port registry tuple family/protocol unsupported")
	ErrOwnerRequired    = errors.New("traversal: lease owner is required")
	ErrInstanceLocked   = errors.New("traversal: another agent process holds the instance lock")
	ErrInvalidLockPath  = errors.New("traversal: lock path must resolve to a regular file without replacement")
)

// TupleKey identifies one socket ownership tuple. v1 supports family "ipv4"
// with protocol "tcp"; UDP and IPv6 are explicit non-goals of P09 and are
// rejected rather than half-supported (P13 extends the protocol axis).
type TupleKey struct {
	Family   string // "ipv4"
	Protocol string // "tcp"
	Address  string // concrete IPv4 literal or "0.0.0.0" wildcard
	Port     uint16 // 0 requests an OS-assigned port
}

// normalize maps an unspecified address to the canonical wildcard.
func (k TupleKey) normalize() TupleKey {
	if k.Address == "" || k.Address == "::" || k.Address == "0.0.0.0" {
		k.Address = "0.0.0.0"
	}
	return k
}

// overlaps reports whether two concrete keys conflict: same family, protocol
// and port, with equal or wildcard addresses.
func (k TupleKey) overlaps(other TupleKey) bool {
	if k.Family != other.Family || k.Protocol != other.Protocol || k.Port != other.Port {
		return false
	}
	if k.Address == other.Address || k.Address == "0.0.0.0" || other.Address == "0.0.0.0" {
		return true
	}
	return false
}

// String renders the tuple for logs and error messages.
func (k TupleKey) String() string {
	return fmt.Sprintf("%s/%s/%s:%d", k.Family, k.Protocol, k.Address, k.Port)
}

// Lease owns one actual OS listener. The registry entry is removed only
// after the OS close succeeds, so a failed close keeps ownership.
type Lease struct {
	Listener   net.Listener
	Actual     TupleKey
	owner      string
	generation uint64
	registry   *PortRegistry
}

// Owner returns the lease owner identity.
func (l *Lease) Owner() string { return l.owner }

// Generation returns the registry generation the lease was issued at.
func (l *Lease) Generation() uint64 { return l.generation }

// Release closes the owned socket and removes the registry entry, but only
// while the entry still matches this owner and generation. A stale release
// returns ErrStaleLease and never touches the current owner's socket.
func (l *Lease) Release() error {
	registry := l.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry, ok := registry.entries[l.Actual]
	if !ok || entry.owner != l.owner || entry.generation != l.generation || entry.lease != l {
		return ErrStaleLease
	}
	if err := l.Listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		// Retain the registry entry when the OS close fails. Dropping
		// ownership before a successful close would permit a new lease to
		// overlap a live descriptor and would let a later stale Release
		// close the new owner.
		return err
	}
	// net.ErrClosed means the descriptor is provably already gone (the
	// documented delete flow is Forward.Close then Release): treat it as a
	// successful close so the tuple can be re-acquired instead of leaving
	// a ghost entry that blocks delete->recreate until process restart.
	delete(registry.entries, l.Actual)
	return nil
}

type leaseEntry struct {
	owner      string
	generation uint64
	lease      *Lease
}

// PortRegistry is the Agent-global socket-ownership table.
type PortRegistry struct {
	mu         sync.Mutex
	entries    map[TupleKey]leaseEntry
	generation uint64
}

// NewPortRegistry returns an empty registry.
func NewPortRegistry() *PortRegistry {
	return &PortRegistry{entries: make(map[TupleKey]leaseEntry)}
}

// Acquire validates the tuple, checks overlap, creates/binds/listens the
// actual socket, resolves the actual port, and publishes the entry — all
// inside one critical section. The returned lease is the sole owner of the
// tuple for its lifetime.
func (r *PortRegistry) Acquire(ctx context.Context, owner string, key TupleKey) (*Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if owner == "" {
		return nil, ErrOwnerRequired
	}
	if key.Family != "ipv4" || key.Protocol != "tcp" {
		return nil, ErrUnsupportedTuple
	}
	key = key.normalize()
	if key.Port != 0 && r.overlapsLocked(key) {
		return nil, ErrTupleOverlap
	}

	socket, err := listenTCP4(ctx, key)
	if err != nil {
		return nil, err
	}
	actual := key
	actual.Port = uint16(socket.Addr().(*net.TCPAddr).Port)
	if r.overlapsLocked(actual) {
		// Defensive: the OS allocated a port that conflicts with an existing
		// entry (cannot happen while the lock is held, but never publish a
		// tuple that overlaps).
		_ = socket.Close()
		return nil, ErrTupleOverlap
	}

	r.generation++
	lease := &Lease{
		Listener:   socket,
		Actual:     actual,
		owner:      owner,
		generation: r.generation,
		registry:   r,
	}
	r.entries[actual] = leaseEntry{owner: owner, generation: lease.generation, lease: lease}
	return lease, nil
}

func (r *PortRegistry) overlapsLocked(candidate TupleKey) bool {
	for existing := range r.entries {
		if existing.overlaps(candidate) {
			return true
		}
	}
	return false
}

// Len returns the number of held tuples.
func (r *PortRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// Has reports whether the normalized tuple is currently owned.
func (r *PortRegistry) Has(key TupleKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.entries[key.normalize()]
	return ok
}

// listenTCP4 creates the actual socket inside the registry critical section.
// The Linux and generic variants are byte-identical; the split exists so a
// future platform-specific listener hardening (e.g. socket options) stays
// behind one seam without weakening the atomic ownership contract.
func listenTCP4(ctx context.Context, key TupleKey) (net.Listener, error) {
	address := net.JoinHostPort(key.Address, strconv.Itoa(int(key.Port)))
	return (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
}

// InstanceLock is the OS-level single-instance lock. The path is never
// unlinked on close; the open flock inode is the lock.
type InstanceLock struct {
	file *os.File
	once sync.Once
	err  error
}

// Close releases the lock and the descriptor exactly once.
func (l *InstanceLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.once.Do(func() {
		l.err = errors.Join(unlockInstance(l.file), l.file.Close())
	})
	return l.err
}
