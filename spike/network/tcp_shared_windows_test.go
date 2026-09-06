//go:build windows

package network

import (
	"context"
	"net"
	"testing"
)

// This baseline is intentionally native-only. Cross-compilation proves only
// that the fixture builds; a Windows result must come from executing this test
// on a real Windows host before shared-port support can be promoted.
func TestTCPBaselineWithoutPrebindReuseConflictsWindows(t *testing.T) {
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
	if err == nil {
		t.Fatal("dial unexpectedly reused a listening tuple without pre-bind options")
	}
}
