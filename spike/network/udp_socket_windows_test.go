//go:build windows

package network

import (
	"net"
	"os"
	"testing"
	"time"
)

// This gate must execute on native Windows. Cross-compilation is not runtime
// evidence and therefore leaves UDP support unpromoted.
func TestWindowsUnconnectedUDPLoopSurvivesICMPReset(t *testing.T) {
	if os.Getenv("ANTINAT_RUN_NATIVE_WINDOWS_UDP") != "1" {
		t.Skip("set ANTINAT_RUN_NATIVE_WINDOWS_UDP=1 on a native Windows host")
	}
	closedSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("allocate closed destination: %v", err)
	}
	closedAddress := closedSocket.LocalAddr().(*net.UDPAddr)
	closedSocket.Close()

	ingress, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open ingress: %v", err)
	}
	defer ingress.Close()
	if _, err := ingress.WriteToUDP([]byte("icmp-trigger"), closedAddress); err != nil {
		t.Fatalf("send ICMP trigger: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open client: %v", err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP([]byte("after-icmp"), ingress.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send follow-up: %v", err)
	}
	ingress.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	n, _, err := ingress.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("unconnected receive loop terminated after ICMP (SIO_UDP_CONNRESET handling required): %v", err)
	}
	if string(buffer[:n]) != "after-icmp" {
		t.Fatalf("payload = %q, want after-icmp", buffer[:n])
	}
}
