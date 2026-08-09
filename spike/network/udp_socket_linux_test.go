//go:build linux

package network

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSingleUDPSocketForwardsTargetResponseFromPublishedTuple(t *testing.T) {
	target, stopTarget := startUDPEchoTarget(t)
	defer stopTarget()
	ingress, err := OpenSingleUDPSocket(&net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, 65_507, 8)
	if err != nil {
		t.Fatalf("open ingress: %v", err)
	}
	defer ingress.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open client: %v", err)
	}
	defer client.Close()

	if _, err := client.WriteToUDP([]byte("payload"), ingress.LocalAddr()); err != nil {
		t.Fatalf("send client payload: %v", err)
	}
	datagram, err := ingress.ReadOne(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatalf("read ingress payload: %v", err)
	}
	if datagram.Kind != DatagramData || string(datagram.Payload) != "payload" {
		t.Fatalf("ingress datagram = %s %q, want DATA payload", datagram.Kind, datagram.Payload)
	}
	if err := ingress.ForwardToTarget(context.Background(), datagram.Source, target, datagram.Payload, 2*time.Second); err != nil {
		t.Fatalf("forward to target: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 64)
	n, source, err := client.ReadFromUDP(response)
	if err != nil {
		t.Fatalf("read target response: %v", err)
	}
	if string(response[:n]) != "echo:payload" {
		t.Fatalf("response = %q, want echo:payload", response[:n])
	}
	if source.String() != ingress.LocalAddr().String() {
		t.Fatalf("response source = %s, want published tuple %s", source, ingress.LocalAddr())
	}
}

func startUDPEchoTarget(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open UDP target: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buffer := make([]byte, 65_507)
		n, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		connection.WriteToUDP(append([]byte("echo:"), buffer[:n]...), source)
	}()
	return connection.LocalAddr().(*net.UDPAddr), func() {
		connection.Close()
		<-stopped
	}
}

func TestSingleUDPSocketDropsTruncatedDatagramAndContinues(t *testing.T) {
	ingress, err := OpenSingleUDPSocket(&net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, 8, 8)
	if err != nil {
		t.Fatalf("open ingress: %v", err)
	}
	defer ingress.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open client: %v", err)
	}
	defer client.Close()

	if _, err := client.WriteToUDP(make([]byte, 32), ingress.LocalAddr()); err != nil {
		t.Fatalf("send oversized datagram: %v", err)
	}
	if _, err := ingress.ReadOne(time.Now().Add(2 * time.Second)); !errors.Is(err, ErrDatagramTruncated) {
		t.Fatalf("oversized read error = %v, want ErrDatagramTruncated", err)
	}
	if got := ingress.TruncatedDatagrams(); got != 1 {
		t.Fatalf("truncated count = %d, want 1", got)
	}

	if _, err := client.WriteToUDP([]byte("ok"), ingress.LocalAddr()); err != nil {
		t.Fatalf("send follow-up datagram: %v", err)
	}
	datagram, err := ingress.ReadOne(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatalf("read after truncation: %v", err)
	}
	if datagram.Kind != DatagramData || string(datagram.Payload) != "ok" {
		t.Fatalf("follow-up datagram = %s %q, want DATA ok", datagram.Kind, datagram.Payload)
	}
}

func TestSingleUDPSocketContinuesAfterCorrelatedICMPPortUnreachable(t *testing.T) {
	closedSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("allocate closed destination: %v", err)
	}
	closedAddress := closedSocket.LocalAddr().(*net.UDPAddr)
	closedSocket.Close()

	ingress, err := OpenSingleUDPSocket(&net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, 64, 8)
	if err != nil {
		t.Fatalf("open ingress: %v", err)
	}
	defer ingress.Close()
	if _, err := ingress.connection.WriteToUDP([]byte("icmp-trigger"), closedAddress); err != nil {
		t.Fatalf("send ICMP trigger: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open client: %v", err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP([]byte("after-icmp"), ingress.LocalAddr()); err != nil {
		t.Fatalf("send follow-up datagram: %v", err)
	}
	datagram, err := ingress.ReadOne(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatalf("read after ICMP: %v", err)
	}
	if string(datagram.Payload) != "after-icmp" {
		t.Fatalf("payload after ICMP = %q, want after-icmp", datagram.Payload)
	}
}

func TestSingleUDPSocketDemuxesSTUNProbeAndData(t *testing.T) {
	ingress, err := OpenSingleUDPSocket(&net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, 512, 8)
	if err != nil {
		t.Fatalf("open ingress: %v", err)
	}
	defer ingress.Close()
	stunServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open STUN source: %v", err)
	}
	defer stunServer.Close()
	provider, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open provider source: %v", err)
	}
	defer provider.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("open data source: %v", err)
	}
	defer client.Close()

	deadline := time.Now().Add(2 * time.Second)
	transaction := [12]byte{1, 2, 3}
	ingress.demux.ExpectSTUN(stunServer.LocalAddr().(*net.UDPAddr), STUNSuccessResponse, transaction, deadline)
	if _, err := stunServer.WriteToUDP(EncodeSTUNFixture(STUNSuccessResponse, transaction), ingress.LocalAddr()); err != nil {
		t.Fatalf("send STUN: %v", err)
	}
	assertNextDatagramKind(t, ingress, deadline, DatagramSTUN)

	key := []byte("provider-key-for-socket-fixture")
	probe := UDPProbeFields{ProbeID: [16]byte{1}, Activation: [16]byte{2}, Endpoint: ingress.LocalAddr(), Challenge: [32]byte{3}}
	ingress.demux.ExpectProbe(provider.LocalAddr().(*net.UDPAddr), probe, key, deadline)
	if _, err := provider.WriteToUDP(EncodeUDPProbeFixture(probe, key), ingress.LocalAddr()); err != nil {
		t.Fatalf("send probe: %v", err)
	}
	assertNextDatagramKind(t, ingress, deadline, DatagramProbe)

	if _, err := client.WriteToUDP([]byte("business-data"), ingress.LocalAddr()); err != nil {
		t.Fatalf("send data: %v", err)
	}
	assertNextDatagramKind(t, ingress, deadline, DatagramData)
}

func assertNextDatagramKind(t *testing.T, ingress *SingleUDPSocket, deadline time.Time, want DatagramKind) {
	t.Helper()
	datagram, err := ingress.ReadOne(deadline)
	if err != nil {
		t.Fatalf("read %s datagram: %v", want, err)
	}
	if datagram.Kind != want {
		t.Fatalf("datagram kind = %s, want %s", datagram.Kind, want)
	}
}
