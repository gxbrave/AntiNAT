package network

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestHiddenChallengeRequiresWANIngressBeforeAuthenticatedCompletion(t *testing.T) {
	providerPublic, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}
	nodePublic, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	now := time.Now()
	arm := ProbeArm{
		ProbeID:           [16]byte{1},
		ProviderID:        [16]byte{2},
		ProviderPublicKey: providerPublic,
		ExpectedSourceIP:  [4]byte{198, 51, 100, 20},
		Activation:        [16]byte{3},
		Endpoint:          "203.0.113.9:3111",
		TTL:               time.Second,
		ExpiryOpaque:      [16]byte{4},
	}
	agent := NewProbeAgent(nodePrivate, 4)
	armed, err := agent.Arm(arm, now)
	if err != nil {
		t.Fatalf("arm probe: %v", err)
	}
	if !VerifyArmed(nodePublic, arm, armed) {
		t.Fatal("probe_armed signature did not verify")
	}

	challenge := [32]byte{9, 8, 7, 6, 5}
	armBytes, err := arm.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal arm: %v", err)
	}
	if bytes.Contains(armBytes, challenge[:]) {
		t.Fatal("provider challenge leaked into control arm")
	}
	frame, err := SignProviderFrame(providerPrivate, arm, challenge)
	if err != nil {
		t.Fatalf("sign provider frame: %v", err)
	}
	outcome, ack, receipt := agent.HandleIngress([4]byte{198, 51, 100, 20}, frame, now.Add(100*time.Millisecond))
	if outcome != ProbeAccepted {
		t.Fatalf("ingress outcome = %s, want ACCEPTED", outcome)
	}
	if !VerifyProbeCompletion(nodePublic, arm, frame, ack, receipt) {
		t.Fatal("same-path ACK and control receipt did not join to one operation")
	}
	if len(ack.MarshalBinary()) > len(frame.MarshalBinary()) {
		t.Fatalf("UDP ACK length = %d, exceeds request length %d", len(ack.MarshalBinary()), len(frame.MarshalBinary()))
	}
}

func TestHiddenChallengeUsesOneGenericRejectionForInvalidIngress(t *testing.T) {
	providerPublic, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	arm := ProbeArm{
		ProbeID: [16]byte{1}, ProviderID: [16]byte{2}, ProviderPublicKey: providerPublic,
		ExpectedSourceIP: [4]byte{198, 51, 100, 20}, Activation: [16]byte{3},
		Endpoint: "203.0.113.9:3111", TTL: time.Second, ExpiryOpaque: [16]byte{4},
	}
	challenge := [32]byte{9}

	tests := []struct {
		name   string
		source [4]byte
		at     time.Time
		mutate func(*ProviderFrame)
		resign bool
	}{
		{name: "wrong source", source: [4]byte{198, 51, 100, 21}, at: now, resign: true},
		{name: "wrong activation", source: arm.ExpectedSourceIP, at: now, mutate: func(frame *ProviderFrame) { frame.Activation = [16]byte{8} }, resign: true},
		{name: "wrong endpoint", source: arm.ExpectedSourceIP, at: now, mutate: func(frame *ProviderFrame) { frame.Endpoint = "203.0.113.9:9999" }, resign: true},
		{name: "wrong opaque expiry", source: arm.ExpectedSourceIP, at: now, mutate: func(frame *ProviderFrame) { frame.ExpiryOpaque = [16]byte{8} }, resign: true},
		{name: "bad signature", source: arm.ExpectedSourceIP, at: now, mutate: func(frame *ProviderFrame) { frame.Signature[0] ^= 0xff }},
		{name: "expired ttl", source: arm.ExpectedSourceIP, at: now.Add(2 * time.Second), resign: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agent := NewProbeAgent(nodePrivate, 4)
			if _, err := agent.Arm(arm, now); err != nil {
				t.Fatalf("arm: %v", err)
			}
			frame, err := SignProviderFrame(providerPrivate, arm, challenge)
			if err != nil {
				t.Fatalf("frame: %v", err)
			}
			if test.mutate != nil {
				test.mutate(&frame)
			}
			if test.resign {
				frame.Signature = ed25519.Sign(providerPrivate, frame.signingBytes())
			}
			outcome, ack, receipt := agent.HandleIngress(test.source, frame, test.at)
			if outcome != ProbeRejected {
				t.Fatalf("outcome = %s, want generic REJECTED", outcome)
			}
			if len(ack.Signature) != 0 || len(receipt.Signature) != 0 {
				t.Fatal("rejected ingress produced authenticated response material")
			}
		})
	}
}

func TestHiddenChallengeRejectsReplayAndBoundsScannerAttempts(t *testing.T) {
	providerPublic, providerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	arm := ProbeArm{
		ProbeID: [16]byte{1}, ProviderID: [16]byte{2}, ProviderPublicKey: providerPublic,
		ExpectedSourceIP: [4]byte{198, 51, 100, 20}, Activation: [16]byte{3},
		Endpoint: "203.0.113.9:3111", TTL: time.Second, ExpiryOpaque: [16]byte{4},
	}
	frame, err := SignProviderFrame(providerPrivate, arm, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}

	replayAgent := NewProbeAgent(nodePrivate, 4)
	replayAgent.Arm(arm, now)
	if outcome, _, _ := replayAgent.HandleIngress(arm.ExpectedSourceIP, frame, now); outcome != ProbeAccepted {
		t.Fatalf("first ingress = %s, want ACCEPTED", outcome)
	}
	if outcome, _, _ := replayAgent.HandleIngress(arm.ExpectedSourceIP, frame, now); outcome != ProbeRejected {
		t.Fatalf("replay = %s, want REJECTED", outcome)
	}

	limitedAgent := NewProbeAgent(nodePrivate, 2)
	limitedAgent.Arm(arm, now)
	for attempt := 0; attempt < 2; attempt++ {
		if outcome, _, _ := limitedAgent.HandleIngress([4]byte{198, 51, 100, 21}, frame, now); outcome != ProbeRejected {
			t.Fatalf("scanner attempt %d = %s, want REJECTED", attempt, outcome)
		}
	}
	if outcome, _, _ := limitedAgent.HandleIngress(arm.ExpectedSourceIP, frame, now); outcome != ProbeRejected {
		t.Fatalf("over-budget valid frame = %s, want REJECTED", outcome)
	}
}

func TestControlOnlyAgentCannotForgeUnknownProviderChallenge(t *testing.T) {
	providerPublic, providerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	arm := ProbeArm{
		ProbeID: [16]byte{1}, ProviderID: [16]byte{2}, ProviderPublicKey: providerPublic,
		ExpectedSourceIP: [4]byte{198, 51, 100, 20}, Activation: [16]byte{3},
		Endpoint: "203.0.113.9:3111", TTL: time.Second, ExpiryOpaque: [16]byte{4},
	}
	actualFrame, err := SignProviderFrame(providerPrivate, arm, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	armBytes, _ := arm.MarshalBinary()
	digest := sha256.Sum256(armBytes)
	guessedHash := sha256.Sum256([]byte("challenge unavailable on control channel"))
	forgedACK := ProbeACK{ArmDigest: digest, ChallengeHash: guessedHash}
	forgedACK.Signature = ed25519.Sign(nodePrivate, forgedACK.signingBytes())
	forgedReceipt := ProbeReceipt{ArmDigest: digest, ChallengeHash: guessedHash, ProviderID: arm.ProviderID}
	forgedReceipt.Signature = ed25519.Sign(nodePrivate, forgedReceipt.signingBytes())
	if VerifyProbeCompletion(nodePublic, arm, actualFrame, forgedACK, forgedReceipt) {
		t.Fatal("control-only challenge guess completed a probe without WAN ingress")
	}
}

func TestHiddenChallengeTCPACKReturnsOnIngressConnection(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen TCP probe endpoint: %v", err)
	}
	defer listener.Close()
	providerPublic, providerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	arm := ProbeArm{
		ProbeID: [16]byte{1}, ProviderID: [16]byte{2}, ProviderPublicKey: providerPublic,
		ExpectedSourceIP: [4]byte{127, 0, 0, 1}, Activation: [16]byte{3},
		Endpoint: listener.Addr().String(), TTL: 2 * time.Second, ExpiryOpaque: [16]byte{4},
	}
	agent := NewProbeAgent(nodePrivate, 4)
	agent.Arm(arm, now)
	frame, err := SignProviderFrame(providerPrivate, arm, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	frameBytes := frame.MarshalBinary()
	type serverResult struct {
		receipt ProbeReceipt
		err     error
	}
	result := make(chan serverResult, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			result <- serverResult{err: err}
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		received := make([]byte, len(frameBytes))
		if _, err := io.ReadFull(connection, received); err != nil {
			result <- serverResult{err: err}
			return
		}
		if !bytes.Equal(received, frameBytes) {
			result <- serverResult{err: fmt.Errorf("received TCP frame differs")}
			return
		}
		source := connection.RemoteAddr().(*net.TCPAddr).IP.To4()
		outcome, ack, receipt := agent.HandleIngress([4]byte{source[0], source[1], source[2], source[3]}, frame, time.Now())
		if outcome != ProbeAccepted {
			result <- serverResult{err: fmt.Errorf("outcome %s", outcome)}
			return
		}
		if _, err := connection.Write(ack.MarshalBinary()); err != nil {
			result <- serverResult{err: err}
			return
		}
		result <- serverResult{receipt: receipt}
	}()

	providerConnection, err := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial TCP probe endpoint: %v", err)
	}
	defer providerConnection.Close()
	providerConnection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := providerConnection.Write(frameBytes); err != nil {
		t.Fatalf("write provider frame: %v", err)
	}
	ackBytes := make([]byte, len((ProbeACK{}).signingBytes())+ed25519.SignatureSize)
	if _, err := io.ReadFull(providerConnection, ackBytes); err != nil {
		t.Fatalf("read same-connection ACK: %v", err)
	}
	server := <-result
	if server.err != nil {
		t.Fatal(server.err)
	}
	challengeHash := sha256.Sum256(frame.Challenge[:])
	ack := ProbeACK{ArmDigest: frame.ArmDigest, ChallengeHash: challengeHash, Signature: append([]byte(nil), ackBytes[len((ProbeACK{}).signingBytes()):]...)}
	if !VerifyProbeCompletion(nodePublic, arm, frame, ack, server.receipt) {
		t.Fatal("TCP same-connection ACK and control receipt failed verification")
	}
}

func TestHiddenChallengeUDPACKReturnsFromPublishedTuple(t *testing.T) {
	agentSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen UDP probe endpoint: %v", err)
	}
	defer agentSocket.Close()
	providerSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen UDP provider: %v", err)
	}
	defer providerSocket.Close()
	providerPublic, providerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	arm := ProbeArm{
		ProbeID: [16]byte{1}, ProviderID: [16]byte{2}, ProviderPublicKey: providerPublic,
		ExpectedSourceIP: [4]byte{127, 0, 0, 1}, Activation: [16]byte{3},
		Endpoint: agentSocket.LocalAddr().String(), TTL: 2 * time.Second, ExpiryOpaque: [16]byte{4},
	}
	agent := NewProbeAgent(nodePrivate, 4)
	agent.Arm(arm, now)
	frame, err := SignProviderFrame(providerPrivate, arm, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	frameBytes := frame.MarshalBinary()
	receipts := make(chan ProbeReceipt, 1)
	errorsSeen := make(chan error, 1)
	go func() {
		buffer := make([]byte, len(frameBytes))
		agentSocket.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, source, err := agentSocket.ReadFromUDP(buffer)
		if err != nil {
			errorsSeen <- err
			return
		}
		if !bytes.Equal(buffer[:n], frameBytes) {
			errorsSeen <- fmt.Errorf("received UDP frame differs")
			return
		}
		sourceIP := source.IP.To4()
		outcome, ack, receipt := agent.HandleIngress([4]byte{sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]}, frame, time.Now())
		if outcome != ProbeAccepted {
			errorsSeen <- fmt.Errorf("outcome %s", outcome)
			return
		}
		if _, err := agentSocket.WriteToUDP(ack.MarshalBinary(), source); err != nil {
			errorsSeen <- err
			return
		}
		receipts <- receipt
	}()
	if _, err := providerSocket.WriteToUDP(frameBytes, agentSocket.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send UDP provider frame: %v", err)
	}
	providerSocket.SetReadDeadline(time.Now().Add(2 * time.Second))
	ackBytes := make([]byte, len((ProbeACK{}).signingBytes())+ed25519.SignatureSize)
	n, source, err := providerSocket.ReadFromUDP(ackBytes)
	if err != nil {
		t.Fatalf("read UDP ACK: %v", err)
	}
	if source.String() != agentSocket.LocalAddr().String() {
		t.Fatalf("UDP ACK source = %s, want published tuple %s", source, agentSocket.LocalAddr())
	}
	if n != len(ackBytes) {
		t.Fatalf("UDP ACK bytes = %d, want %d", n, len(ackBytes))
	}
	select {
	case err := <-errorsSeen:
		t.Fatal(err)
	case receipt := <-receipts:
		challengeHash := sha256.Sum256(frame.Challenge[:])
		ack := ProbeACK{ArmDigest: frame.ArmDigest, ChallengeHash: challengeHash, Signature: append([]byte(nil), ackBytes[len((ProbeACK{}).signingBytes()):]...)}
		if !VerifyProbeCompletion(nodePublic, arm, frame, ack, receipt) {
			t.Fatal("UDP same-path ACK and control receipt failed verification")
		}
	}
}
