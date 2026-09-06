package harness

import (
	"net"
	"testing"
	"time"
)

func TestWaitForEndpointReleaseHeldListenerTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if reserved, err := waitForEndpointRelease(ln.Addr().String(), 100*time.Millisecond); err == nil {
		_ = reserved.Close()
		t.Fatal("held listener reported as released")
	}
}

func TestWaitForEndpointReleaseObservesClosedListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := ln.Addr().String()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = ln.Close()
	}()

	reserved, err := waitForEndpointRelease(endpoint, time.Second)
	if err != nil {
		t.Fatalf("closed listener did not become bindable: %v", err)
	}
	defer reserved.Close()
}
