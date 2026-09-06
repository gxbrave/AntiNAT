package controller

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestIPv6ControlListener is Story 5 cycle-2 RED evidence: the controller
// control/API listener must accept the configured IPv6 socket rather than
// forcing a tcp4-only listener.
func TestIPv6ControlListener(t *testing.T) {
	app, err := New(Config{
		ListenAddress: "[::1]:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Start(); err != nil {
		t.Fatalf("Start on IPv6 listener: %v", err)
	}
	defer app.Shutdown(context.Background())
	conn, err := net.DialTimeout("tcp6", app.Addr(), time.Second)
	if err != nil {
		t.Fatalf("dial IPv6 controller listener: %v", err)
	}
	conn.Close()
}
