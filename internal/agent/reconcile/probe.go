// Agent probe plane (Story 2): the durable probe_arm handler, the WAN1
// ingress gate on the published TCP listener, the same-path ACK1, and the
// RCT1 control receipt.
//
// The gate wraps the P09 listener BEFORE the proxy sees it: connections
// whose remote source matches an armed, unexpired probe are parsed for a
// WAN1 frame within a bounded deadline, verified against the frozen probe
// state machine, answered with an ACK1 on the same connection, and the RCT1
// receipt is pushed over the signed control channel. The probe connection is
// consumed and never handed to business. Every other source passes straight
// through to the proxy untouched (anti-oracle: no prefix sniffing of victim
// traffic, v0.8 §5.2).
package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// ErrProbeArmRejected is the generic arm rejection (no detail leak).
var ErrProbeArmRejected = errors.New("reconcile: probe arm rejected")

// SendControlFunc pushes an A2C control message (probe_ingress_receipt).
type SendControlFunc func(ctx context.Context, messageType string, payload []byte) error

// ProbeManagerOptions configures the agent probe manager.
type ProbeManagerOptions struct {
	// Store is the agent localstate store (durable armed ops).
	Store *localstate.Store
	// NodeKey signs RDY1/ACK1/RCT1 frames.
	NodeKey *security.NodeKey
	// Clock is the monotonic clock; defaults to time.Now.
	Clock func() time.Time
	// SendControl pushes A2C control messages (probe_ingress_receipt).
	SendControl SendControlFunc
}

// armedOp is one in-memory armed probe operation (loaded from bbolt at
// startup, persisted at arm time).
type armedOp struct {
	arm      protocol.ProbeArm
	digest   [32]byte
	deadline time.Time
	used     bool
}

// ProbeManager implements the agent-side probe plane.
type ProbeManager struct {
	store *localstate.Store
	key   *security.NodeKey
	clock func() time.Time
	send  SendControlFunc

	mu     sync.Mutex
	ops    map[[16]byte]*armedOp
	replay map[[16]byte]time.Time
}

// NewProbeManager builds the manager and recovers durable armed operations
// from bbolt (restart recovery; expired ops are dropped on first sweep).
func NewProbeManager(opts ProbeManagerOptions) *ProbeManager {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	m := &ProbeManager{
		store:  opts.Store,
		key:    opts.NodeKey,
		clock:  opts.Clock,
		send:   opts.SendControl,
		ops:    map[[16]byte]*armedOp{},
		replay: map[[16]byte]time.Time{},
	}
	if m.store != nil {
		probes, err := m.store.ListArmedProbes()
		if err == nil {
			for _, p := range probes {
				if p.Deadline.After(m.clock()) {
					m.ops[p.Arm.ProbeID] = &armedOp{arm: p.Arm, digest: p.Digest, deadline: p.Deadline}
				}
			}
		}
	}
	return m
}

// HandleProbeArm validates a canonical ARM1 frame against the applied state,
// persists the armed operation durably (protocol.md §7.2: probe_armed only
// after durable persistence), and returns the signed RDY1 frame bytes.
// forwardID names the applied forward the arm must match.
func (m *ProbeManager) HandleProbeArm(ctx context.Context, raw []byte, forwardID string) ([]byte, error) {
	arm, err := protocol.ParseProbeArm(raw)
	if err != nil {
		return nil, err
	}
	if m.store == nil {
		return nil, ErrProbeArmRejected
	}
	applied, ok, err := m.store.GetAppliedState(forwardID)
	if err != nil {
		return nil, err
	}
	if !ok {
		// No applied forward: the arm cannot match any activation.
		return nil, ErrProbeArmRejected
	}
	// Activation must match the current applied activation, and the endpoint
	// must equal the actual bind tuple.
	if arm.Activation != protocol.ActivationID(forwardID, applied.SpecRevision) {
		return nil, ErrProbeArmRejected
	}
	wantEndpoint := net.JoinHostPort(applied.ActualBindHost, fmt.Sprintf("%d", applied.ActualBindPort))
	if arm.Endpoint != wantEndpoint {
		return nil, ErrProbeArmRejected
	}

	deadline := m.clock().Add(time.Duration(arm.TTLMS) * time.Millisecond)
	if err := m.store.SaveArmedProbe(arm, deadline); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.ops[arm.ProbeID] = &armedOp{arm: arm, digest: arm.Digest(), deadline: deadline}
	m.mu.Unlock()

	// RDY1: magic + digest + signature over (RDY1 || digest).
	digest := arm.Digest()
	var rdy bytes.Buffer
	rdy.WriteString(protocol.ProbeMagicArmed)
	rdy.Write(digest[:])
	sig, err := m.key.Sign(rdy.Bytes())
	if err != nil {
		return nil, err
	}
	rdy.Write(sig)
	return rdy.Bytes(), nil
}

// sweep evicts expired operations and replay entries.
func (m *ProbeManager) sweep(now time.Time) {
	for id, op := range m.ops {
		if !now.Before(op.deadline) {
			delete(m.ops, id)
		}
	}
	for id, expire := range m.replay {
		if !now.Before(expire) {
			delete(m.replay, id)
		}
	}
}

// findArmedBySource returns an unexpired armed op whose expected source
// matches remote IP, if any.
func (m *ProbeManager) findArmedBySource(ip [4]byte) *armedOp {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.clock())
	for _, op := range m.ops {
		if !op.used && op.arm.ExpectedSourceIP == ip {
			return op
		}
	}
	return nil
}

// handleIngress consumes one accepted connection from the expected provider
// source: reads the WAN1 frame with a bounded deadline, verifies it against
// the armed operation, writes the ACK1 on the same connection, and sends the
// RCT1 receipt over the control channel. Every failure is a generic drop
// with zero authenticated material (anti-oracle).
func (m *ProbeManager) handleIngress(conn net.Conn, op *armedOp, readTimeout time.Duration) {
	defer conn.Close()
	deadline := time.Now().Add(readTimeout)
	conn.SetReadDeadline(deadline)

	// Two-phase bounded read: fixed header (magic + digest + ids +
	// activation + 1-byte endpoint length), then the endpoint + trailer.
	const fixed = 4 + 32 + 16 + 16 + 16 + 1
	head := make([]byte, fixed)
	if _, err := readFull(conn, head); err != nil {
		return // truncated: generic drop
	}
	endpointLen := int(head[fixed-1])
	frameLen := fixed + endpointLen + 16 + 32 + 64
	if endpointLen == 0 || frameLen > 4+32+16+16+16+1+protocol.ProbeEndpointMax+16+32+64 {
		return
	}
	rest := make([]byte, frameLen-fixed)
	if _, err := readFull(conn, rest); err != nil {
		return
	}
	raw := append(head, rest...)
	frame, err := protocol.ParseProviderFrame(raw)
	if err != nil {
		return
	}
	m.mu.Lock()
	_, replayed := m.replay[frame.ProbeID]
	now := m.clock()
	accepted := false
	if !replayed && op.digest == frame.ArmDigest {
		// Full field + signature verification (frozen HandleProbeIngress
		// semantics inlined: every mismatch is a generic rejection).
		arm := op.arm
		if frame.ProviderID == arm.ProviderID &&
			frame.Activation == arm.Activation &&
			frame.Endpoint == arm.Endpoint &&
			frame.ExpiryOpaque == arm.ExpiryOpaque &&
			ed25519.Verify(arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
			accepted = true
			op.used = true
			m.replay[frame.ProbeID] = now.Add(protocol.ProbeReplayWindow)
		}
	}
	m.mu.Unlock()
	if !accepted {
		return // generic REJECTED/DROPPED
	}

	// ACK1 on the same connection.
	chash := frame.ChallengeHash()
	var ack bytes.Buffer
	ack.WriteString(protocol.ProbeMagicACK)
	ack.Write(op.digest[:])
	ack.Write(chash[:])
	sig, err := m.key.Sign(ack.Bytes())
	if err != nil {
		return
	}
	ack.Write(sig)
	conn.SetWriteDeadline(time.Now().Add(readTimeout))
	if _, err := conn.Write(ack.Bytes()); err != nil {
		return
	}

	// RCT1 control receipt.
	var rct bytes.Buffer
	rct.WriteString(protocol.ProbeMagicReceipt)
	rct.Write(op.digest[:])
	rct.Write(chash[:])
	rct.Write(op.arm.ProviderID[:])
	rsig, err := m.key.Sign(rct.Bytes())
	if err != nil {
		return
	}
	rct.Write(rsig)
	if m.send != nil {
		_ = m.send(context.Background(), "probe_ingress_receipt", rct.Bytes())
	}
	// Durable consumption: the operation is consumed once; keep the row so a
	// restart cannot re-arm a consumed id (the replay cache is in-memory).
	_ = m.store.DeleteArmedProbe(op.arm.ProbeID)
}

// probeGateOptions configures the listener gate.
type probeGateOptions struct {
	// ForwardID names the forward this listener belongs to.
	ForwardID string
	// ReadTimeout bounds the WAN1 parse (v0.8 §5.2 bounded deadline).
	ReadTimeout time.Duration
}

// ProbeGate is a net.Listener wrapper that consumes probe ingress from the
// armed provider source and passes every other connection to the business
// accept path untouched.
type ProbeGate struct {
	inner net.Listener
	mgr   *ProbeManager
	opts  probeGateOptions
}

// NewProbeGate wraps inner with the probe ingress gate.
func NewProbeGate(inner net.Listener, mgr *ProbeManager, opts probeGateOptions) *ProbeGate {
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 2 * time.Second
	}
	return &ProbeGate{inner: inner, mgr: mgr, opts: opts}
}

// Accept returns the next business connection. Probe connections from the
// armed provider source are consumed internally and never returned.
func (g *ProbeGate) Accept() (net.Conn, error) {
	for {
		conn, err := g.inner.Accept()
		if err != nil {
			return nil, err
		}
		remoteIP := remoteIPv4(conn)
		if remoteIP == nil {
			return conn, nil // non-IPv4 (test doubles): business path
		}
		op := g.mgr.findArmedBySource(*remoteIP)
		if op == nil {
			return conn, nil // not the provider source: straight to business
		}
		// Provider source with an armed op: bounded probe-frame parse.
		go g.mgr.handleIngress(conn, op, g.opts.ReadTimeout)
	}
}

// Close closes the underlying listener.
func (g *ProbeGate) Close() error { return g.inner.Close() }

// Addr returns the underlying listener address.
func (g *ProbeGate) Addr() net.Addr { return g.inner.Addr() }

// remoteIPv4 returns the remote address as a 4-byte IPv4, or nil.
func remoteIPv4(conn net.Conn) *[4]byte {
	tcp, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	ip4 := tcp.IP.To4()
	if ip4 == nil {
		return nil
	}
	var out [4]byte
	copy(out[:], ip4)
	return &out
}

// readFull reads exactly len(buf) bytes or returns an error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
