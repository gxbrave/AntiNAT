//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestTCPBaselineWithoutPrebindReuseConflicts(t *testing.T) {
	localListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen baseline local: %v", err)
	}
	defer localListener.Close()
	remoteListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen baseline remote: %v", err)
	}
	defer remoteListener.Close()

	dialer := net.Dialer{LocalAddr: localListener.Addr()}
	connection, err := dialer.DialContext(context.Background(), "tcp4", remoteListener.Addr().String())
	if connection != nil {
		connection.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("dial without pre-bind reuse error = %v, want EADDRINUSE", err)
	}
}

func TestTCPSharedPortRoutesListenerAndConnectedSocketsByFourTuple(t *testing.T) {
	const connectedSockets = 3
	remotes := make([]string, 0, connectedSockets)
	results := make([]<-chan error, 0, connectedSockets)
	for i := 0; i < connectedSockets; i++ {
		address, result := startTCPMarkerServer(t, byte('A'+i), byte('a'+i))
		remotes = append(remotes, address)
		results = append(results, result)
	}

	fixture, err := OpenTCPSharedPort(context.Background(), net.ParseIP("127.0.0.1"), remotes)
	if err != nil {
		t.Fatalf("open shared-port fixture: %v", err)
	}
	defer fixture.Close()

	shared := fixture.Listener.Addr().(*net.TCPAddr)
	if shared.Port == 0 {
		t.Fatal("listener retained port 0 instead of the OS-assigned port")
	}
	if len(fixture.Connected) != connectedSockets {
		t.Fatalf("connected sockets = %d, want %d", len(fixture.Connected), connectedSockets)
	}

	for i, connection := range fixture.Connected {
		local := connection.LocalAddr().(*net.TCPAddr)
		if !local.IP.Equal(shared.IP) || local.Port != shared.Port {
			t.Fatalf("connection %d local tuple = %s, want %s", i, local, shared)
		}
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set connection %d deadline: %v", i, err)
		}
		marker := []byte{0}
		if _, err := io.ReadFull(connection, marker); err != nil {
			t.Fatalf("read marker from connection %d: %v", i, err)
		}
		if want := byte('A' + i); marker[0] != want {
			t.Fatalf("connection %d marker = %q, want %q", i, marker[0], want)
		}
		if _, err := connection.Write([]byte{byte('a' + i)}); err != nil {
			t.Fatalf("write response on connection %d: %v", i, err)
		}
	}

	client, err := net.DialTimeout("tcp4", shared.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial shared listener: %v", err)
	}
	defer client.Close()
	accepted, err := fixture.Listener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept shared listener connection: %v", err)
	}
	defer accepted.Close()
	if !accepted.LocalAddr().(*net.TCPAddr).IP.Equal(shared.IP) || accepted.LocalAddr().(*net.TCPAddr).Port != shared.Port {
		t.Fatalf("accepted local tuple = %s, want %s", accepted.LocalAddr(), shared)
	}

	for i, result := range results {
		if err := <-result; err != nil {
			t.Fatalf("remote %d: %v", i, err)
		}
	}
}

func TestTCPSharedPortCloseAllowsExactTupleRebind(t *testing.T) {
	first, err := OpenTCPSharedPort(context.Background(), net.ParseIP("127.0.0.1"), nil)
	if err != nil {
		t.Fatalf("open first fixture: %v", err)
	}
	address := first.Listener.Addr().(*net.TCPAddr)
	if err := first.Close(); err != nil {
		t.Fatalf("close first fixture: %v", err)
	}

	second, err := OpenTCPSharedPortAt(context.Background(), address, nil)
	if err != nil {
		t.Fatalf("rebind exact tuple %s: %v", address, err)
	}
	defer second.Close()
	if got := second.Listener.Addr().String(); got != address.String() {
		t.Fatalf("rebound tuple = %s, want %s", got, address)
	}
}

func TestTCPSharedPortPreservesWriteHalfAfterRemoteCloseWrite(t *testing.T) {
	remoteListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen half-close remote: %v", err)
	}
	defer remoteListener.Close()
	result := make(chan error, 1)
	go func() {
		connection, err := remoteListener.AcceptTCP()
		if err != nil {
			result <- fmt.Errorf("accept: %w", err)
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := connection.Write([]byte("request")); err != nil {
			result <- fmt.Errorf("write request: %w", err)
			return
		}
		if err := connection.CloseWrite(); err != nil {
			result <- fmt.Errorf("close write half: %w", err)
			return
		}
		response, err := io.ReadAll(connection)
		if err != nil {
			result <- fmt.Errorf("read response: %w", err)
			return
		}
		if string(response) != "response" {
			result <- fmt.Errorf("response = %q, want response", response)
			return
		}
		result <- nil
	}()

	fixture, err := OpenTCPSharedPort(context.Background(), net.ParseIP("127.0.0.1"), []string{remoteListener.Addr().String()})
	if err != nil {
		t.Fatalf("open half-close fixture: %v", err)
	}
	defer fixture.Close()
	connection := fixture.Connected[0]
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read through remote FIN: %v", err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q, want request", request)
	}
	if _, err := connection.Write([]byte("response")); err != nil {
		t.Fatalf("write after remote FIN: %v", err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatalf("close local write half: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func startTCPMarkerServer(t *testing.T, sent, expected byte) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen marker server: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			result <- fmt.Errorf("accept: %w", err)
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			result <- fmt.Errorf("set deadline: %w", err)
			return
		}
		if _, err := connection.Write([]byte{sent}); err != nil {
			result <- fmt.Errorf("write marker: %w", err)
			return
		}
		response := []byte{0}
		if _, err := io.ReadFull(connection, response); err != nil {
			result <- fmt.Errorf("read response: %w", err)
			return
		}
		if response[0] != expected {
			result <- fmt.Errorf("response = %q, want %q", response[0], expected)
			return
		}
		result <- nil
	}()
	return listener.Addr().String(), result
}
