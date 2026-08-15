package probe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestProviderRejectsUnsignedRequest covers the anti-abuse boundary: a
// request without a valid controller signature is refused before any network
// activity.
func TestProviderRejectsUnsignedRequest(t *testing.T) {
	ctrlPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	// Tampered signature.
	req := providerRequest{
		Schema: providerRequestSchema, ProbeID: "aa", Endpoint: "198.51.100.7:80",
		Signature: "00",
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/probe/v1/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res providerResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Accepted {
		t.Fatal("unsigned request accepted")
	}
	if res.Reason != "bad_request" {
		t.Fatalf("reason = %q, want bad_request", res.Reason)
	}
}

// TestProviderRefusesPrivateEndpoint covers anti-abuse: private/CGNAT/
// loopback endpoints are rejected without dialing.
func TestProviderRefusesPrivateEndpoint(t *testing.T) {
	ctrlPub, ctrlPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req := providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "k1",
		NodePublicKey: strings.Repeat("11", ed25519.PublicKeySize), NodePublicKeyHash: hex.EncodeToString(hash256(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize))),
		ProbeID: strings.Repeat("33", 16), ProviderID: strings.Repeat("44", 16), Activation: strings.Repeat("55", 16),
		Endpoint: "10.0.0.1:80", ExpectedSourceIP: "7f000001", ExpiryOpaque: strings.Repeat("66", 16),
		TTLMS: 30000, ArmDigest: strings.Repeat("77", 32), TimestampUnix: time.Now().Unix(),
	}
	canonical, _ := req.canonical()
	req.Signature = hex.EncodeToString(ed25519.Sign(ctrlPriv, canonical))
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/probe/v1/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res providerResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Accepted {
		t.Fatal("private endpoint accepted")
	}
	if res.Reason != "invalid_endpoint" {
		t.Fatalf("reason = %q, want invalid_endpoint", res.Reason)
	}
}

// TestProviderReplayCacheIsBounded covers the resource bound: unique probe
// ids cannot grow the TTL replay map without limit.
func TestProviderReplayCacheIsBounded(t *testing.T) {
	ctrlPub, ctrlPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
		MaxReplayEntries:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	for _, id := range []string{strings.Repeat("88", 16), strings.Repeat("99", 16)} {
		req := providerRequest{
			Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "k1",
			NodePublicKey: strings.Repeat("11", ed25519.PublicKeySize), NodePublicKeyHash: hex.EncodeToString(hash256(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize))),
			ProbeID: id, ProviderID: strings.Repeat("44", 16), Activation: strings.Repeat("55", 16),
			Endpoint: "10.0.0.1:80", ExpectedSourceIP: "7f000001", ExpiryOpaque: strings.Repeat("66", 16),
			TTLMS: 30000, ArmDigest: strings.Repeat("77", 32), TimestampUnix: time.Now().Unix(),
		}
		canonical, _ := req.canonical()
		req.Signature = hex.EncodeToString(ed25519.Sign(ctrlPriv, canonical))
		body, _ := json.Marshal(req)
		resp, err := http.Post(srv.URL+"/probe/v1/request", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if got := p.Stats().ReplayCache; got != 1 {
		t.Fatalf("replay cache size = %d, want 1", got)
	}
}

// TestProviderFullExchange covers the happy path: a signed request leads to a
// WAN1 dial, an agent-style ACK1 answer, and an accepted signed result with
// the challenge hash and both frames.
func TestProviderFullExchange(t *testing.T) {
	ctrlPub, ctrlPriv, _ := ed25519.GenerateKey(rand.Reader)
	provPub, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
		DialTimeout:         2 * time.Second,
		ExchangeTimeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	// The agent's published listener (TEST-NET global literal on lo).
	_ = provPub
	ln, endpoint := globalTestEndpoint(t)

	nodePub, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	var digest [32]byte
	rand.Read(digest[:])
	var probeID, providerID, activation, opaque [16]byte
	rand.Read(probeID[:])
	rand.Read(providerID[:])
	rand.Read(activation[:])
	rand.Read(opaque[:])

	// The agent answers WAN1 with ACK1 (signed by the node key).
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, err := readWAN1(conn)
		if err != nil {
			return
		}
		frame, err := protocol.ParseProviderFrame(raw)
		if err != nil {
			return
		}
		chash := frame.ChallengeHash()
		ackBody := append([]byte(protocol.ProbeMagicACK), digest[:]...)
		ackBody = append(ackBody, chash[:]...)
		ackBody = append(ackBody, ed25519.Sign(nodePriv, ackBody)...)
		conn.Write(ackBody)
	}()

	req := providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "k1",
		NodePublicKey:     hex.EncodeToString(nodePub),
		NodePublicKeyHash: hex.EncodeToString(hash256(nodePub)),
		ProbeID:           hex.EncodeToString(probeID[:]), ProviderID: hex.EncodeToString(providerID[:]),
		Activation: hex.EncodeToString(activation[:]), Endpoint: endpoint,
		ExpectedSourceIP: "7f000001", ExpiryOpaque: hex.EncodeToString(opaque[:]),
		TTLMS: 30000, ArmDigest: hex.EncodeToString(digest[:]),
		TimestampUnix: time.Now().Unix(),
	}
	canonical, _ := req.canonical()
	req.Signature = hex.EncodeToString(ed25519.Sign(ctrlPriv, canonical))
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/probe/v1/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res providerResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if !res.Accepted {
		t.Fatalf("exchange not accepted: reason=%q", res.Reason)
	}
	if res.ChallengeHash == "" || res.WAN1Frame == "" || res.ACK1Frame == "" {
		t.Fatalf("incomplete result: %+v", res)
	}
	// The result must verify with the provider public key.
	if !res.verify(provPub) {
		t.Fatal("result signature does not verify with provider key")
	}
	// The ACK1 frame must verify with the node key.
	ackBytes, _ := hex.DecodeString(res.ACK1Frame)
	if _, err := protocol.ParseProbeACK(ackBytes, nodePub); err != nil {
		t.Fatalf("returned ACK1 invalid: %v", err)
	}
}
