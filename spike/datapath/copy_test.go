package datapath

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"
)

func TestEligibleAndBufferedTCPPathsPreservePayload(t *testing.T) {
	payload := bytes.Repeat([]byte("AntiNAT-data-path\n"), 1<<16)
	wantHash := sha256.Sum256(payload)
	for _, spliceEligible := range []bool{true, false} {
		name := "buffered"
		if spliceEligible {
			name = "eligible"
		}
		t.Run(name, func(t *testing.T) {
			got, copied := exerciseTCPPath(t, payload, spliceEligible)
			if copied != int64(len(payload)) {
				t.Fatalf("copied = %d, want %d", copied, len(payload))
			}
			if gotHash := sha256.Sum256(got); gotHash != wantHash {
				t.Fatalf("payload hash mismatch: got %x want %x", gotHash, wantHash)
			}
		})
	}
}

func exerciseTCPPath(t *testing.T, payload []byte, spliceEligible bool) ([]byte, int64) {
	t.Helper()
	destination, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	source, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	received := make(chan []byte, 1)
	receiveErr := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			receiveErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		data, err := io.ReadAll(conn)
		if err != nil {
			receiveErr <- err
			return
		}
		received <- data
	}()

	copiedResult := make(chan int64, 1)
	proxyErr := make(chan error, 1)
	go func() {
		inbound, err := source.Accept()
		if err != nil {
			proxyErr <- err
			return
		}
		defer inbound.Close()
		outbound, err := net.DialTCP("tcp4", nil, destination.Addr().(*net.TCPAddr))
		if err != nil {
			proxyErr <- err
			return
		}
		defer outbound.Close()
		inbound.(*net.TCPConn).SetDeadline(time.Now().Add(10 * time.Second))
		outbound.SetDeadline(time.Now().Add(10 * time.Second))
		copied, err := CopyTCP(outbound, inbound.(*net.TCPConn), spliceEligible)
		if err != nil {
			proxyErr <- err
			return
		}
		if err := outbound.CloseWrite(); err != nil {
			proxyErr <- err
			return
		}
		copiedResult <- copied
	}()

	client, err := net.DialTCP("tcp4", nil, source.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	client.Close()

	var copied int64
	select {
	case err := <-proxyErr:
		t.Fatal(err)
	case copied = <-copiedResult:
	case <-time.After(12 * time.Second):
		t.Fatal("proxy timed out")
	}
	select {
	case err := <-receiveErr:
		t.Fatal(err)
	case data := <-received:
		return data, copied
	case <-time.After(12 * time.Second):
		t.Fatal("receiver timed out")
	}
	return nil, 0
}
