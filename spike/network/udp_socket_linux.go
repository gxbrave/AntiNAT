//go:build linux

package network

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrDatagramTruncated = errors.New("UDP datagram exceeded the bounded read buffer")

type Datagram struct {
	Kind    DatagramKind
	Payload []byte
	Source  *net.UDPAddr
}

type SingleUDPSocket struct {
	connection        *net.UDPConn
	demux             *UDPDemux
	buffer            []byte
	truncated         atomic.Uint64
	recoverableErrors atomic.Uint64
}

func OpenSingleUDPSocket(address *net.UDPAddr, maxDatagram, maxSessions int) (*SingleUDPSocket, error) {
	if maxDatagram <= 0 || maxDatagram > 65_507 {
		return nil, errors.New("max datagram must be between 1 and 65507 bytes")
	}
	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		return nil, err
	}
	return &SingleUDPSocket{
		connection: connection,
		demux:      NewUDPDemux(maxSessions),
		buffer:     make([]byte, maxDatagram),
	}, nil
}

func (socket *SingleUDPSocket) LocalAddr() *net.UDPAddr {
	return cloneUDPAddr(socket.connection.LocalAddr().(*net.UDPAddr))
}

func (socket *SingleUDPSocket) Close() error {
	return socket.connection.Close()
}

func (socket *SingleUDPSocket) ReadOne(deadline time.Time) (Datagram, error) {
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
		return Datagram{Kind: socket.demux.Classify(source, payload, time.Now()), Payload: payload, Source: cloneUDPAddr(source)}, nil
	}
}

// ForwardToTarget performs a bounded target round trip and sends the response
// through the original unconnected ingress socket.
func (socket *SingleUDPSocket) ForwardToTarget(ctx context.Context, client, target *net.UDPAddr, payload []byte, timeout time.Duration) error {
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
