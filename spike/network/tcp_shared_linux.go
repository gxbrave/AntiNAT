//go:build linux

// Package network contains disposable feasibility fixtures. None of this code is
// a production networking API; later plans consume only its recorded findings.
package network

import (
	"context"
	"errors"
	"net"
	"syscall"
)

const soReusePort = 15

// TCPSharedPort owns one listener and connected sockets sharing its concrete
// local tuple. The process-level ownership spike is responsible for ensuring
// that no second process joins this Linux reuse group.
type TCPSharedPort struct {
	Listener  *net.TCPListener
	Connected []*net.TCPConn
}

// OpenTCPSharedPort binds the listener first, keeps it open, and then binds each
// outgoing connection to the listener's OS-assigned tuple before connecting to
// a distinct remote tuple.
func OpenTCPSharedPort(ctx context.Context, sourceIP net.IP, remoteAddresses []string) (*TCPSharedPort, error) {
	return OpenTCPSharedPortAt(ctx, &net.TCPAddr{IP: sourceIP}, remoteAddresses)
}

// OpenTCPSharedPortAt is the exact-tuple form used by close/rebind evidence.
func OpenTCPSharedPortAt(ctx context.Context, source *net.TCPAddr, remoteAddresses []string) (*TCPSharedPort, error) {
	listenConfig := net.ListenConfig{Control: enableAddressReuse}
	listenerSocket, err := listenConfig.Listen(ctx, "tcp4", source.String())
	if err != nil {
		return nil, err
	}
	listener, ok := listenerSocket.(*net.TCPListener)
	if !ok {
		listenerSocket.Close()
		return nil, errors.New("tcp4 listen did not return *net.TCPListener")
	}

	fixture := &TCPSharedPort{Listener: listener}
	local := listener.Addr().(*net.TCPAddr)
	for _, remoteAddress := range remoteAddresses {
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: append(net.IP(nil), local.IP...), Port: local.Port},
			Control:   enableAddressReuse,
		}
		connectionSocket, err := dialer.DialContext(ctx, "tcp4", remoteAddress)
		if err != nil {
			fixture.Close()
			return nil, err
		}
		connection, ok := connectionSocket.(*net.TCPConn)
		if !ok {
			connectionSocket.Close()
			fixture.Close()
			return nil, errors.New("tcp4 dial did not return *net.TCPConn")
		}
		fixture.Connected = append(fixture.Connected, connection)
	}
	return fixture, nil
}

func enableAddressReuse(_ string, _ string, raw syscall.RawConn) error {
	var socketError error
	if err := raw.Control(func(fd uintptr) {
		socketError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if socketError == nil {
			socketError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		}
	}); err != nil {
		return err
	}
	return socketError
}

// Close releases connected sockets before the unique listener.
func (fixture *TCPSharedPort) Close() error {
	var joined error
	for _, connection := range fixture.Connected {
		joined = errors.Join(joined, connection.Close())
	}
	if fixture.Listener != nil {
		joined = errors.Join(joined, fixture.Listener.Close())
	}
	return joined
}
