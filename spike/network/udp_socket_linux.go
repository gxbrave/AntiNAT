//go:build linux

package network

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	ErrDatagramTruncated = errors.New("UDP datagram exceeded the bounded read buffer")
	ErrForwardLimit      = errors.New("UDP target-forward concurrency limit reached")
)

type Datagram struct {
	Kind     DatagramKind
	Payload  []byte
	Source   *net.UDPAddr
	Response []byte
	Receipt  *ProbeReceipt
}

type SingleUDPSocket struct {
	connection        *net.UDPConn
	demux             *UDPDemux
	buffer            []byte
	forwardSlots      chan struct{}
	closeOnce         sync.Once
	closeErr          error
	truncated         atomic.Uint64
	recoverableErrors atomic.Uint64
}

func OpenSingleUDPSocket(address *net.UDPAddr, maxDatagram, maxSessions int) (*SingleUDPSocket, error) {
	return OpenSingleUDPSocketWithLimits(address, maxDatagram, maxSessions, 16)
}

func OpenSingleUDPSocketWithLimits(address *net.UDPAddr, maxDatagram, maxSessions, maxForwards int) (*SingleUDPSocket, error) {
	if address == nil || maxDatagram <= 0 || maxDatagram > 65_507 || maxForwards <= 0 {
		return nil, errors.New("UDP socket requires a concrete address, bounded datagram, and positive forward limit")
	}
	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		return nil, err
	}
	return &SingleUDPSocket{connection: connection, demux: NewUDPDemux(maxSessions), buffer: make([]byte, maxDatagram), forwardSlots: make(chan struct{}, maxForwards)}, nil
}

func (socket *SingleUDPSocket) LocalAddr() *net.UDPAddr {
	if socket == nil || socket.connection == nil {
		return nil
	}
	return cloneUDPAddr(socket.connection.LocalAddr().(*net.UDPAddr))
}

func (socket *SingleUDPSocket) Close() error {
	if socket == nil || socket.connection == nil {
		return nil
	}
	socket.closeOnce.Do(func() { socket.closeErr = socket.connection.Close() })
	return socket.closeErr
}

func (socket *SingleUDPSocket) ReadOne(deadline time.Time) (Datagram, error) {
	if socket == nil || socket.connection == nil || !deadline.After(time.Time{}) {
		return Datagram{}, errors.New("UDP socket and future deadline are required")
	}
	if err := socket.connection.SetReadDeadline(deadline); err != nil {
		return Datagram{}, err
	}
	for {
		n, _, flags, source, err := socket.connection.ReadMsgUDP(socket.buffer, nil)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
				socket.recoverableErrors.Add(1)
				continue
			}
			return Datagram{}, err
		}
		if flags&syscall.MSG_TRUNC != 0 {
			socket.truncated.Add(1)
			return Datagram{}, ErrDatagramTruncated
		}
		payload := append([]byte(nil), socket.buffer[:n]...)
		kind, response, receipt := socket.demux.ClassifyWithResponse(source, payload, time.Now())
		return Datagram{Kind: kind, Payload: payload, Source: cloneUDPAddr(source), Response: append([]byte(nil), response...), Receipt: receipt}, nil
	}
}

func (socket *SingleUDPSocket) AttachProbeAgent(agent *ProbeAgent) {
	if socket != nil && socket.demux != nil {
		socket.demux.AttachProbeAgent(agent)
	}
}

// WriteResponse sends an authenticated provider ACK from the same unconnected
// ingress socket that received the frame.
func (socket *SingleUDPSocket) WriteResponse(datagram Datagram) error {
	if socket == nil || socket.connection == nil || datagram.Source == nil || len(datagram.Response) == 0 {
		return errors.New("datagram has no same-path response")
	}
	if err := socket.connection.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	_, err := socket.connection.WriteToUDP(datagram.Response, datagram.Source)
	return err
}

// ForwardToTarget performs a bounded target round trip and sends the response
// through the original unconnected ingress socket.
func (socket *SingleUDPSocket) ForwardToTarget(ctx context.Context, client, target *net.UDPAddr, payload []byte, timeout time.Duration) error {
	if socket == nil || socket.connection == nil || client == nil || target == nil || timeout <= 0 {
		return errors.New("forward requires socket, client, target, and positive timeout")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case socket.forwardSlots <- struct{}{}:
		defer func() { <-socket.forwardSlots }()
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ErrForwardLimit
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	targetConnection, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		return err
	}
	defer targetConnection.Close()
	if err := targetConnection.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := targetConnection.Write(payload); err != nil {
		return err
	}
	response := make([]byte, 65_507)
	n, err := targetConnection.Read(response)
	if err != nil {
		return err
	}
	if err := socket.connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err = socket.connection.WriteToUDP(response[:n], client)
	return err
}

func (socket *SingleUDPSocket) TruncatedDatagrams() uint64 {
	return socket.truncated.Load()
}

func (socket *SingleUDPSocket) RecoverableErrors() uint64 {
	return socket.recoverableErrors.Load()
}
