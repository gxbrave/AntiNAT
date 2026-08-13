// Story 3 RED: STUN over TCP framing and persistent client. Frames are read
// from the stream via the STUN header length (RFC 8489 §6.2.2: STUN-only TCP
// needs no additional framing), tolerating partial header/body reads,
// rejecting oversize declarations, and surfacing disconnect and timeout
// cleanly. There is no STUN-layer retransmission over TCP (RFC 8489 §6.2.2);
// a disconnect before the response fails the transaction and invalidates the
// mapping candidate (v0.8 §3.5).
package stun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeTCPServer accepts one connection and answers Binding requests with
// XOR-MAPPED-ADDRESS. The handler receives the raw request and can emit
// custom byte sequences, close the connection, or stay silent.
type fakeTCPServer struct {
	listener net.Listener
	addr     netip.AddrPort
	mu       sync.Mutex
	requests []*Message
	// rawWrites, when set, replaces the normal reply path: each element is
	// written verbatim to the connection.
	rawWrites [][]byte
	// closeAfter, when set, closes the connection after that many requests.
	closeAfter int
	// silent, when set, never replies.
	silent bool
	// chunked, when set, writes replies one byte at a time.
	chunked bool
}

func newFakeTCPServer(t *testing.T) *fakeTCPServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake tcp listen: %v", err)
	}
	server := &fakeTCPServer{
		listener: listener,
		addr:     listener.Addr().(*net.TCPAddr).AddrPort(),
	}
	go server.serve(t)
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *fakeTCPServer) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(t, conn)
	}
}

func (s *fakeTCPServer) handle(t *testing.T, conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		msg, err := ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.requests = append(s.requests, msg)
		raw := s.rawWrites
		closeAfter := s.closeAfter
		silent := s.silent
		chunked := s.chunked
		count := len(s.requests)
		s.mu.Unlock()
		if closeAfter > 0 && count >= closeAfter {
			return
		}
		if silent {
			continue
		}
		if len(raw) > 0 {
			// Raw path: emit the configured bytes (possibly truncated /
			// malformed) then close the connection so the client observes
			// the failure immediately.
			wire := raw[count-1]
			if chunked {
				for _, b := range wire {
					if _, err := conn.Write([]byte{b}); err != nil {
						return
					}
					time.Sleep(time.Millisecond)
				}
			} else if _, err := conn.Write(wire); err != nil {
				return
			}
			return
		}
		reply := &Message{Type: MessageTypeBindingSuccess, TransactionID: msg.TransactionID}
		_ = reply.AddXORMappedAddress(conn.LocalAddr().(*net.TCPAddr).AddrPort())
		wire, err := reply.Marshal()
		if err != nil {
			return
		}
		if chunked {
			for _, b := range wire {
				if _, err := conn.Write([]byte{b}); err != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		} else if _, err := conn.Write(wire); err != nil {
			return
		}
	}
}

func (s *fakeTCPServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func TestTCPExchangeSuccess(t *testing.T) {
	server := newFakeTCPServer(t)
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if reply.Type != MessageTypeBindingSuccess || reply.TransactionID != req.TransactionID {
		t.Fatalf("unexpected reply type/txid")
	}
	if server.requestCount() != 1 {
		t.Fatalf("server saw %d requests, want 1", server.requestCount())
	}
	select {
	case <-client.Disconnected():
		t.Fatal("connection reported disconnected while healthy")
	default:
	}
}

func TestTCPFramePartialHeaderAndBody(t *testing.T) {
	// The server dribbles the reply one byte at a time; the framing reader
	// must reassemble header and body from partial reads.
	server := newFakeTCPServer(t)
	server.mu.Lock()
	server.chunked = true
	server.mu.Unlock()
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	reply, err := client.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if reply.TransactionID != req.TransactionID {
		t.Fatalf("txid mismatch")
	}
}

func TestTCPFrameOversizeRejected(t *testing.T) {
	// A frame whose declared length exceeds the client's bound must be
	// rejected with ErrOversize and poison the connection.
	header := make([]byte, 20)
	header[0], header[1] = 0x00, 0x01
	header[2], header[3] = 0xff, 0xfc // declared 65532
	header[4], header[5], header[6], header[7] = 0x21, 0x12, 0xa4, 0x42
	server := newFakeTCPServer(t)
	server.mu.Lock()
	server.rawWrites = [][]byte{header}
	server.mu.Unlock()
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{MaxMessageSize: 1024})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	_, err = client.Exchange(context.Background(), req)
	if !errors.Is(err, ErrOversize) {
		t.Fatalf("Exchange = %v, want ErrOversize", err)
	}
}

func TestTCPDisconnectMidFrame(t *testing.T) {
	// The server sends only the 20-byte header then closes; the reader must
	// surface a disconnect error and invalidate the mapping.
	header := make([]byte, 20)
	header[0], header[1] = 0x00, 0x01
	header[2], header[3] = 0x00, 0x08
	header[4], header[5], header[6], header[7] = 0x21, 0x12, 0xa4, 0x42
	server := newFakeTCPServer(t)
	server.mu.Lock()
	server.rawWrites = [][]byte{header}
	server.mu.Unlock()
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	_, err = client.Exchange(context.Background(), req)
	if !errors.Is(err, ErrDisconnected) {
		t.Fatalf("Exchange = %v, want ErrDisconnected", err)
	}
	select {
	case <-client.Disconnected():
	default:
		t.Fatal("Disconnected() not signaled after mid-frame disconnect")
	}
}

func TestTCPTimeoutNoRetransmit(t *testing.T) {
	// A silent server must produce ErrTimeout after the configured deadline
	// and exactly one request on the wire (no STUN-layer retransmit over
	// TCP, RFC 8489 §6.2.2).
	server := newFakeTCPServer(t)
	server.mu.Lock()
	server.silent = true
	server.mu.Unlock()
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	_, err = client.Exchange(context.Background(), req)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Exchange = %v, want ErrTimeout", err)
	}
	if server.requestCount() != 1 {
		t.Fatalf("server saw %d requests, want exactly 1 (no retransmit)", server.requestCount())
	}
}

func TestTCPPersistentMultipleExchanges(t *testing.T) {
	// One connection carries several sequential transactions (RFC 8489
	// §6.2.2: a client MAY send multiple transactions over one connection).
	server := newFakeTCPServer(t)
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	for i := 0; i < 3; i++ {
		req := NewBindingRequest([12]byte{byte(i + 1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
		reply, err := client.Exchange(context.Background(), req)
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if reply.TransactionID != req.TransactionID {
			t.Fatalf("exchange %d: txid mismatch", i)
		}
	}
	if server.requestCount() != 3 {
		t.Fatalf("server saw %d requests, want 3", server.requestCount())
	}
}

func TestTCPConcurrentExchanges(t *testing.T) {
	// Pipelined requests on one connection must be demultiplexed by
	// transaction ID (RFC 8489 §6.2.2 permits another request before the
	// previous response).
	server := newFakeTCPServer(t)
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	reqA := NewBindingRequest([12]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	reqB := NewBindingRequest([12]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2})
	results := make(chan error, 2)
	go func() {
		reply, err := client.Exchange(context.Background(), reqA)
		if err == nil && reply.TransactionID != reqA.TransactionID {
			err = errors.New("A received wrong transaction")
		}
		results <- err
	}()
	go func() {
		reply, err := client.Exchange(context.Background(), reqB)
		if err == nil && reply.TransactionID != reqB.TransactionID {
			err = errors.New("B received wrong transaction")
		}
		results <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent exchange: %v", err)
		}
	}
}

func TestTCPMappingInvalidationAfterServerClose(t *testing.T) {
	// When the server closes the connection, Disconnected() must fire and a
	// subsequent Exchange must fail fast with ErrDisconnected (v0.8 §3.5:
	// TCP disconnect immediately invalidates the mapping candidate).
	server := newFakeTCPServer(t)
	client, err := DialTCP(context.Background(), server.addr.String(), TCPClientOptions{})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	// Tell the server to close after the first request (raw path: write
	// nothing, closeAfter=1 means the handler returns and closes).
	server.mu.Lock()
	server.closeAfter = 1
	server.rawWrites = [][]byte{{}}
	server.mu.Unlock()
	req := NewBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	_, err = client.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("Exchange succeeded, want disconnect error")
	}
	select {
	case <-client.Disconnected():
	default:
		t.Fatal("Disconnected() not signaled after server close")
	}
	_, err = client.Exchange(context.Background(), req)
	if !errors.Is(err, ErrDisconnected) {
		t.Fatalf("exchange after disconnect = %v, want ErrDisconnected", err)
	}
}

var _ = io.EOF
var _ = netip.AddrPort{}
