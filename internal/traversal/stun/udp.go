// Transaction-safe STUN UDP client over a caller-owned socket. The client
// never creates or closes the socket; the caller owns it (v0.8 §4.3: STUN is
// consumed only by outstanding transaction ID + exact server tuple + class +
// deadline). A single demux reader routes datagrams to waiters so concurrent
// exchanges on one socket cannot steal each other's responses.
//
// Retransmission follows RFC 8489 §6.2.1: an initial RTO (>= 500 ms,
// doubling after each retransmission), at most Rc requests in total, and a
// final wait of Rm x RTO after the last request. Error 300 Try Alternate
// reattempts the request against the ALTERNATE-SERVER with the same
// transport, using a fresh transaction ID (RFC 8489 §5), bounded by a
// visited-server set and a total alternate cap (RFC 8489 §10).
package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Default UDP client parameters (RFC 8489 §6.2.1).
const (
	DefaultRTO             = 500 * time.Millisecond
	DefaultMaxRequests     = 7  // Rc
	DefaultFinalWaitFactor = 16 // Rm
	DefaultMaxAlternates   = 3
)

// UDP client sentinel errors.
var (
	ErrTimeout       = errors.New("stun: UDP transaction timed out")
	ErrAlternateLoop = errors.New("stun: alternate-server redirection loop")
	ErrClientClosed  = errors.New("stun: UDP client is closed")
	ErrNotARequest   = errors.New("stun: exchange requires a request-class message")
)

// UDPClientOptions tunes the retransmission and redirection policy.
type UDPClientOptions struct {
	RTO             time.Duration // initial retransmission timeout; default 500 ms
	MaxRequests     int           // Rc: total requests; default 7
	FinalWaitFactor int           // Rm: final wait as a multiple of RTO; default 16
	MaxAlternates   int           // total alternate-server hops; default 3
}

func (o UDPClientOptions) withDefaults() UDPClientOptions {
	if o.RTO <= 0 {
		o.RTO = DefaultRTO
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxRequests
	}
	if o.FinalWaitFactor <= 0 {
		o.FinalWaitFactor = DefaultFinalWaitFactor
	}
	if o.MaxAlternates <= 0 {
		o.MaxAlternates = DefaultMaxAlternates
	}
	return o
}

// waiter is one outstanding transaction registered by an Exchange call.
type waiter struct {
	server netip.AddrPort
	method Method
	ch     chan *Message
	done   chan struct{}
	err    error
}

// fail unblocks the waiter with the given error (socket died).
func (w *waiter) fail(err error) {
	w.err = err
	close(w.done)
}

// UDPClient performs transaction-safe STUN exchanges over a caller-owned
// socket. Close stops new exchanges but never closes the socket.
type UDPClient struct {
	conn *net.UDPConn
	opts UDPClientOptions

	mu        sync.Mutex
	waiters   map[TransactionID]*waiter
	started   bool
	readerErr error
	closed    bool
}

// NewUDPClient binds a client to the caller-owned socket.
func NewUDPClient(conn *net.UDPConn, opts UDPClientOptions) *UDPClient {
	return &UDPClient{
		conn:    conn,
		opts:    opts.withDefaults(),
		waiters: make(map[TransactionID]*waiter),
	}
}

// Close marks the client closed; the caller-owned socket is not touched and
// in-flight transactions continue until their own deadline.
func (c *UDPClient) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

// Exchange sends req to server and waits for the matching response. It
// retransmits with doubling RTO until a response, the Rc cap, or the context
// deadline. On 300 Try Alternate with ALTERNATE-SERVER it reattempts against
// the alternate (bounded). The response is accepted only when its source is
// the exact server tuple, its class is success/error, its method matches,
// and its transaction ID matches the request (v0.8 §4.3).
func (c *UDPClient) Exchange(ctx context.Context, server netip.AddrPort, req *Message) (*Message, error) {
	if req.Type.Class() != ClassRequest {
		return nil, ErrNotARequest
	}
	visited := map[netip.AddrPort]bool{server: true}
	for alternates := 0; ; {
		reply, err := c.exchangeOnce(ctx, server, req)
		if err != nil {
			return nil, err
		}
		code, _, codeErr := reply.ErrorCode()
		if codeErr != nil || code != 300 {
			return reply, nil
		}
		alt, altErr := reply.AlternateServer()
		if altErr != nil || visited[alt] || alternates >= c.opts.MaxAlternates {
			return nil, ErrAlternateLoop
		}
		// The current transaction is failed; reattempt against the alternate
		// server with the same transport and a fresh transaction ID
		// (RFC 8489 §10, §5).
		txid, txErr := NewTransactionID()
		if txErr != nil {
			return nil, txErr
		}
		req = &Message{
			Type:          req.Type,
			TransactionID: txid,
			Attributes:    append([]Attribute(nil), req.Attributes...),
		}
		visited[alt] = true
		server = alt
		alternates++
	}
}

// exchangeOnce runs one request/response transaction against a single server.
func (c *UDPClient) exchangeOnce(ctx context.Context, server netip.AddrPort, req *Message) (*Message, error) {
	wire, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	address := net.UDPAddrFromAddrPort(server)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	if c.readerErr != nil {
		err := c.readerErr
		c.mu.Unlock()
		return nil, err
	}
	if !c.started {
		c.started = true
		go c.readerLoop()
	}
	w := &waiter{
		server: server,
		method: req.Type.Method(),
		ch:     make(chan *Message, 1),
		done:   make(chan struct{}),
	}
	c.waiters[req.TransactionID] = w
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, req.TransactionID)
		c.mu.Unlock()
	}()

	if _, err := c.conn.WriteToUDP(wire, address); err != nil {
		return nil, err
	}
	rto := c.opts.RTO
	wait := rto
	for sent := 1; ; sent++ {
		if sent >= c.opts.MaxRequests {
			// Final wait of Rm x RTO after the last request (RFC 8489
			// §6.2.1), still bounded by the caller's deadline.
			return waitResponse(ctx, w, time.Duration(c.opts.FinalWaitFactor)*rto)
		}
		select {
		case msg := <-w.ch:
			return msg, nil
		case <-w.done:
			return nil, w.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		if _, err := c.conn.WriteToUDP(wire, address); err != nil {
			return nil, err
		}
		wait *= 2
	}
}

func waitResponse(ctx context.Context, w *waiter, wait time.Duration) (*Message, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case msg := <-w.ch:
		return msg, nil
	case <-w.done:
		return nil, w.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// readerLoop demultiplexes datagrams to the matching waiter. Datagrams are
// consumed only when the source equals the waiter's exact server tuple, the
// class is success or error, the method matches, and the transaction ID
// matches (v0.8 §4.3). The loop exits when the caller-owned socket fails,
// failing all pending waiters.
func (c *UDPClient) readerLoop() {
	buf := make([]byte, 65507)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.mu.Lock()
			c.readerErr = err
			waiters := make([]*waiter, 0, len(c.waiters))
			for _, w := range c.waiters {
				waiters = append(waiters, w)
			}
			c.mu.Unlock()
			for _, w := range waiters {
				w.fail(err)
			}
			return
		}
		msg, err := ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		class := msg.Type.Class()
		if class != ClassSuccess && class != ClassError {
			continue // wrong class (e.g. an echoed request) is not a response
		}
		source := from.AddrPort()
		c.mu.Lock()
		w, ok := c.waiters[msg.TransactionID]
		if ok && w.server == source && w.method == msg.Type.Method() {
			select {
			case w.ch <- msg:
			default: // waiter already has a response; drop the duplicate
			}
		}
		c.mu.Unlock()
	}
}
