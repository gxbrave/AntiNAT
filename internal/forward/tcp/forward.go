// TCP direct data plane (v0.8 §4.2, §4.4): one listener per Forward tuple,
// bidirectional per-session copy with correct half-close semantics — an EOF
// on one direction propagates CloseWrite to the peer so the other direction
// can finish, and the connections are fully closed only when both directions
// are done. The accept loop survives backend dial failures and paces
// transient accept errors with a bounded backoff instead of busy-looping.
// The data path is the standard-library io.Copy on raw *net.TCPConn (Linux
// splice-eligible); no custom fast path and no runtime splice counters.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT/internal/forward"
)

// Options configures one Forward instance.
type Options struct {
	// Backend is the target snapshot; each session resolves it once at
	// accept time.
	Backend *forward.Backend
	// DialTimeout bounds each backend dial.
	DialTimeout time.Duration
	// AcceptBackoffMin/Max pace transient accept errors (default 10ms/1s,
	// doubling each failure).
	AcceptBackoffMin time.Duration
	AcceptBackoffMax time.Duration
}

// Forward is one TCP forward: it owns the listener and the sessions accepted
// from it. Run executes the accept loop; the listener's owner calls Run in
// its own goroutine.
type Forward struct {
	listener net.Listener
	backend  *forward.Backend

	dialTimeout time.Duration
	backoffMin  time.Duration
	backoffMax  time.Duration

	loopStarted atomic.Bool
	loopDone    chan struct{}
	closed      atomic.Bool

	wg sync.WaitGroup
}

// New validates the options and wraps the listener. The caller owns the
// listener until Run is started.
func New(listener net.Listener, opts Options) (*Forward, error) {
	if listener == nil {
		return nil, errors.New("tcp: listener is required")
	}
	if opts.Backend == nil {
		return nil, errors.New("tcp: backend is required")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.AcceptBackoffMin <= 0 {
		opts.AcceptBackoffMin = 10 * time.Millisecond
	}
	if opts.AcceptBackoffMax <= 0 {
		opts.AcceptBackoffMax = 1 * time.Second
	}
	return &Forward{
		listener:    listener,
		backend:     opts.Backend,
		dialTimeout: opts.DialTimeout,
		backoffMin:  opts.AcceptBackoffMin,
		backoffMax:  opts.AcceptBackoffMax,
		loopDone:    make(chan struct{}),
	}, nil
}

// Run accepts connections until the listener is closed, Close is called, or
// ctx is cancelled. It returns nil when the listener was closed (normal
// shutdown), ctx.Err() on cancellation, and the accept-loop error otherwise.
func (f *Forward) Run(ctx context.Context) error {
	f.loopStarted.Store(true)
	defer close(f.loopDone)

	backoff := f.backoffMin
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			if f.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if isTransientAcceptError(err) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > f.backoffMax {
					backoff = f.backoffMax
				}
				continue
			}
			return err
		}
		backoff = f.backoffMin
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.handleSession(conn)
		}()
	}
}

// handleSession dials the backend snapshot and proxies both directions with
// half-close semantics. A failed backend dial closes the client connection;
// the accept loop is unaffected.
func (f *Forward) handleSession(clientConn net.Conn) {
	defer clientConn.Close()

	targetConn, err := net.DialTimeout("tcp4", f.backend.Target().String(), f.dialTimeout)
	if err != nil {
		return
	}
	defer targetConn.Close()

	clientTCP, clientOK := clientConn.(*net.TCPConn)
	targetTCP, targetOK := targetConn.(*net.TCPConn)
	if !clientOK || !targetOK {
		// Non-TCP transports (test doubles) cannot half-close: fall back to
		// full-duplex copy with full close on either direction's end.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(targetConn, clientConn) }()
		go func() { defer wg.Done(); _, _ = io.Copy(clientConn, targetConn) }()
		wg.Wait()
		return
	}
	proxyTCP(clientTCP, targetTCP)
}

// proxyTCP copies both directions and propagates CloseWrite so a
// server-first or slow-client protocol can finish its reply after the peer
// half-closed, and vice versa. Both sockets are fully closed only after both
// directions are done.
func proxyTCP(client, target *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		_ = target.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		_ = client.CloseWrite()
	}()
	wg.Wait()
	_ = client.Close()
	_ = target.Close()
}

func isTransientAcceptError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED)
}
