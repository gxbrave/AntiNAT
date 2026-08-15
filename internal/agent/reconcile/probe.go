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
	"crypto/sha256"
	"encoding/hex"
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
	// MaxReplayEntries bounds the in-memory replay fence.
	MaxReplayEntries int
	// SweepInterval bounds expired operation/tombstone retention.
	SweepInterval time.Duration
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

	mu            sync.Mutex
	ops           map[[16]byte]*armedOp
	replay        map[[16]byte]time.Time
	maxReplay     int
	sweepInterval time.Duration
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// NewProbeManager builds the manager and recovers durable armed operations
// from bbolt (restart recovery; expired ops are dropped on first sweep).
func NewProbeManager(opts ProbeManagerOptions) *ProbeManager {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.MaxReplayEntries <= 0 {
		opts.MaxReplayEntries = 4096
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = time.Minute
	}
	m := &ProbeManager{
		store:         opts.Store,
		key:           opts.NodeKey,
		clock:         opts.Clock,
		send:          opts.SendControl,
		ops:           map[[16]byte]*armedOp{},
		replay:        map[[16]byte]time.Time{},
		maxReplay:     opts.MaxReplayEntries,
		sweepInterval: opts.SweepInterval,
	}
	if m.store != nil {
		probes, err := m.store.ListArmedProbes()
		if err == nil {
			for _, p := range probes {
				if p.Consumed {
					continue
				}
				if p.Deadline.After(m.clock()) {
					m.ops[p.Arm.ProbeID] = &armedOp{arm: p.Arm, digest: p.Digest, deadline: p.Deadline}
				} else {
					_ = m.store.DeleteArmedProbe(p.Arm.ProbeID)
				}
			}
		}
	}
	return m
}

// Start launches the cancellable probe retention sweeper. It is separate from
// the listener gate so shutdown can wait for all state work before closing the
// local bbolt store.
func (m *ProbeManager) Start(parent context.Context) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				m.mu.Lock()
				m.sweep(now)
				m.mu.Unlock()
				if m.store != nil {
					_ = m.store.SweepArmedProbeTombstones(now)
				}
			}
		}
	}()
}

// Close stops the retention sweeper and waits for it to exit.
func (m *ProbeManager) Close() {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
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
		if errors.Is(err, localstate.ErrProbeConsumed) || errors.Is(err, localstate.ErrProbeConflict) {
			return nil, ErrProbeArmRejected
		}
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

// RetryPendingReceipts resends consumed receipts that were durably recorded
// but not acknowledged by the control sender before a disconnect/crash.
func (m *ProbeManager) RetryPendingReceipts(ctx context.Context) error {
	if m.store == nil || m.send == nil {
		return nil
	}
	probes, err := m.store.ListArmedProbes()
	if err != nil {
		return err
	}
	var firstErr error
	for _, probe := range probes {
		if !probe.Consumed || probe.ReceiptSent || len(probe.Receipt) == 0 {
			continue
		}
		messageID := probe.ReceiptMessageID
		if messageID == "" {
			messageID = probeReceiptMessageID(probe.Receipt)
			_ = m.store.SetArmedProbeReceiptMessageID(probe.Arm.ProbeID, messageID, probe.Deadline.Add(protocol.ProbeReplayWindow))
		}
		if err := m.send(ctx, "probe_ingress_receipt", probe.Receipt); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := m.store.MarkArmedProbeReceiptSent(probe.Arm.ProbeID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// AcknowledgeReceipt consumes the controller semantic receipt for a probe
// ingress message and removes only the matching durable tombstone.
func (m *ProbeManager) AcknowledgeReceipt(operationID string) error {
	if m.store == nil {
		return nil
	}
	return m.store.AcknowledgeArmedProbeReceipt(operationID)
}

// sweep evicts expired operations and replay entries.
func (m *ProbeManager) sweep(now time.Time) {
	for id, op := range m.ops {
		if !now.Before(op.deadline) {
			delete(m.ops, id)
			if m.store != nil {
				_ = m.store.DeleteArmedProbe(id)
			}
		}
	}
	for id, expire := range m.replay {
		if !now.Before(expire) {
			delete(m.replay, id)
		}
	}
}

// hasArmedBySource reports whether a source currently has an armed operation.
// The gate uses this only to decide whether to consume a bounded probe attempt;
// frame-to-operation demultiplexing happens after the frame is parsed.
func (m *ProbeManager) hasArmedBySource(ip [4]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.clock())
	for _, op := range m.ops {
		if !op.used && op.arm.ExpectedSourceIP == ip {
			return true
		}
	}
	return false
}

// handleIngress consumes one accepted connection from the expected provider
// source: reads the WAN1 frame with a bounded deadline, verifies it against
// the armed operation, writes the ACK1 on the same connection, and sends the
// RCT1 receipt over the control channel. Every failure is a generic drop
// with zero authenticated material (anti-oracle).
func (m *ProbeManager) handleIngress(conn net.Conn, source [4]byte, readTimeout time.Duration) {
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

	// Demultiplex only after parsing and authenticating the frame. Selecting
	// the first operation by source alone lets one provider starve another
	// operation armed on the same source IP.
	now := m.clock()
	m.mu.Lock()
	m.sweep(now)
	if _, replayed := m.replay[frame.ProbeID]; replayed {
		m.mu.Unlock()
		return
	}
	var op *armedOp
	for _, candidate := range m.ops {
		if candidate.used || !now.Before(candidate.deadline) || candidate.arm.ExpectedSourceIP != source ||
			candidate.arm.ProbeID != frame.ProbeID || candidate.digest != frame.ArmDigest {
			continue
		}
		arm := candidate.arm
		if frame.ProviderID == arm.ProviderID &&
			frame.Activation == arm.Activation &&
			frame.Endpoint == arm.Endpoint &&
			frame.ExpiryOpaque == arm.ExpiryOpaque &&
			ed25519.Verify(arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
			op = candidate
			break
		}
	}
	if op == nil {
		m.mu.Unlock()
		return // generic REJECTED/DROPPED
	}
	op.used = true
	if len(m.replay) >= m.maxReplay {
		var oldestID [16]byte
		var oldest time.Time
		for id, expires := range m.replay {
			if oldest.IsZero() || expires.Before(oldest) {
				oldestID, oldest = id, expires
			}
		}
		if !oldest.IsZero() {
			delete(m.replay, oldestID)
		}
	}
	m.replay[frame.ProbeID] = now.Add(protocol.ProbeReplayWindow)
	m.mu.Unlock()

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

	// RCT1 is built and durably recorded before the network ACK. If the
	// process crashes after ACK, restart recovery can still resend this exact
	// receipt; if sending fails, the consumed row remains pending.
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
	receiptMessageID := probeReceiptMessageID(rct.Bytes())
	if m.store == nil {
		m.mu.Lock()
		op.used = false
		delete(m.replay, frame.ProbeID)
		m.mu.Unlock()
		return
	}
	if err := m.store.MarkArmedProbeConsumedWithReceipt(op.arm.ProbeID, rct.Bytes(), receiptMessageID, op.deadline.Add(protocol.ProbeReplayWindow)); err != nil {
		m.mu.Lock()
		op.used = false
		delete(m.replay, frame.ProbeID)
		m.mu.Unlock()
		return
	}

	conn.SetWriteDeadline(time.Now().Add(readTimeout))
	if _, err := writeFull(conn, ack.Bytes()); err != nil {
		return
	}
	if m.send != nil {
		ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		err := m.send(ctx, "probe_ingress_receipt", rct.Bytes())
		cancel()
		if err == nil {
			_ = m.store.MarkArmedProbeReceiptSent(op.arm.ProbeID)
		}
	}
}

// probeReceiptMessageID mirrors control.Client.SendMessage's deterministic id
// derivation so the controller can acknowledge an A2C ingress receipt after
// the sink has durably consumed it.
func probeReceiptMessageID(payload []byte) string {
	sum := sha256.Sum256(payload)
	id := security.MessageID(hex.EncodeToString(sum[:]), "probe_ingress_receipt")
	return hex.EncodeToString(id[:])
}

// ProbeGateOptions configures the listener gate.
type ProbeGateOptions struct {
	// ForwardID names the forward this listener belongs to.
	ForwardID string
	// ReadTimeout bounds the WAN1 parse (v0.8 §5.2 bounded deadline).
	ReadTimeout time.Duration
	// MaxConcurrent bounds provider-source probe goroutines.
	MaxConcurrent int
}

// ProbeGate is a net.Listener wrapper that consumes probe ingress from the
// armed provider source and passes every other connection to the business
// accept path untouched.
type ProbeGate struct {
	inner net.Listener
	mgr   *ProbeManager
	opts  ProbeGateOptions
	slots chan struct{}
}

// NewProbeGate wraps inner with the probe ingress gate.
func NewProbeGate(inner net.Listener, mgr *ProbeManager, opts ProbeGateOptions) *ProbeGate {
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 2 * time.Second
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 64
	}
	return &ProbeGate{inner: inner, mgr: mgr, opts: opts, slots: make(chan struct{}, opts.MaxConcurrent)}
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
		if !g.mgr.hasArmedBySource(*remoteIP) {
			return conn, nil // not the provider source: straight to business
		}
		// Provider source with an armed op: bounded probe-frame parse. Never
		// create an unbounded goroutine per source-matching connection.
		select {
		case g.slots <- struct{}{}:
			go func(source [4]byte) {
				defer func() { <-g.slots }()
				g.mgr.handleIngress(conn, source, g.opts.ReadTimeout)
			}(*remoteIP)
		default:
			_ = conn.Close() // generic resource-bound drop
		}
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

// writeFull writes all bytes or returns the first error.
func writeFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Write(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
