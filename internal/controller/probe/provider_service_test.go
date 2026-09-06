package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
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

func TestProviderRejectsSignedRequestPastTTL(t *testing.T) {
	ctrlPub, ctrlPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1000, 0)
	req := providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "k1",
		NodePublicKey: strings.Repeat("11", ed25519.PublicKeySize), NodePublicKeyHash: hex.EncodeToString(hash256(bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize))),
		ProbeID: strings.Repeat("33", 16), ProviderID: strings.Repeat("44", 16), Activation: strings.Repeat("55", 16),
		Endpoint: "198.51.100.7:80", ExpectedSourceIP: "7f000001", ExpiryOpaque: strings.Repeat("66", 16),
		TTLMS: 30000, ArmDigest: strings.Repeat("77", 32), TimestampUnix: now.Unix() - 31,
	}
	canonical, _ := req.canonical()
	req.Signature = hex.EncodeToString(ed25519.Sign(ctrlPriv, canonical))
	body, _ := json.Marshal(req)
	if _, err := decodeProviderRequestAt(bytes.NewReader(body), ctrlPub, now); err == nil {
		t.Fatal("signed provider request was accepted after its TTL")
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

// replay entries are retained through the replay window boundary and
// become reusable only after the boundary has passed. The sweep is driven by
// an explicit timestamp so this test does not sleep on wall-clock time.
func TestProviderReplaySweepHonorsWindowBoundary(t *testing.T) {
	ctrlPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	clock := time.Unix(10_000, 0)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
		Clock:               func() time.Time { return clock },
		ReplayWindow:        time.Minute,
		MaxReplayEntries:    4,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "key",
		NodePublicKey: strings.Repeat("11", ed25519.PublicKeySize), NodePublicKeyHash: strings.Repeat("22", 32),
		ProbeID: strings.Repeat("33", 16), ProviderID: strings.Repeat("44", 16), Activation: strings.Repeat("55", 16),
		Endpoint: "198.51.100.7:80", ExpectedSourceIP: "c6336409", ExpiryOpaque: strings.Repeat("66", 16),
		TTLMS: 30_000, ArmDigest: strings.Repeat("77", 32), TimestampUnix: clock.Unix(),
	}
	if reason := p.admitReplay(req, clock); reason != "" {
		t.Fatalf("initial replay admission = %q", reason)
	}
	if removed := p.SweepReplay(clock.Add(time.Minute - time.Nanosecond)); removed != 0 {
		t.Fatalf("pre-boundary replay sweep removed %d entries, want 0", removed)
	}
	if removed := p.SweepReplay(clock.Add(time.Minute)); removed != 1 {
		t.Fatalf("boundary replay sweep removed %d entries, want 1", removed)
	}
	if reason := p.admitReplay(req, clock.Add(time.Minute)); reason != "" {
		t.Fatalf("reused expired replay id = %q, want accepted", reason)
	}
}

// the replay sweeper must be owned by a context and Close must return
// promptly after cancellation, even when its cadence is long.
func TestProviderReplaySweeperCancellation(t *testing.T) {
	ctrlPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, provPriv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: ctrlPub,
		ProviderPrivateKey:  provPriv,
		ReplaySweepInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		_ = p.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("provider Close did not join the cancelled replay sweeper")
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
	if out, err := exec.Command("ip", "addr", "add", "198.51.100.9/32", "dev", "lo").CombinedOutput(); err != nil {
		_ = out
	}
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", "198.51.100.9/32", "dev", "lo").Run() })

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
		ExpectedSourceIP: "c6336409", ExpiryOpaque: hex.EncodeToString(opaque[:]),
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

func signedAdmissionRequest(t *testing.T, controllerPrivate ed25519.PrivateKey, probeID string) []byte {
	t.Helper()
	nodeBytes := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	req := providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "inst", ControllerKeyID: "k1",
		NodePublicKey: hex.EncodeToString(nodeBytes), NodePublicKeyHash: hex.EncodeToString(hash256(nodeBytes)),
		ProbeID: probeID, ProviderID: strings.Repeat("44", 16), Activation: strings.Repeat("55", 16),
		Endpoint: "10.0.0.1:80", ExpectedSourceIP: "7f000001", ExpiryOpaque: strings.Repeat("66", 16),
		TTLMS: 30_000, ArmDigest: strings.Repeat("77", 32), TimestampUnix: time.Now().Unix(),
	}
	canonical, err := req.canonical()
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(controllerPrivate, canonical))
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestProviderRateLimitedResultRetainsProbeID(t *testing.T) {
	controllerPub, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: controllerPub,
		ProviderPrivateKey:  providerPrivate,
		MaxRequests:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := signedAdmissionRequest(t, controllerPrivate, strings.Repeat("aa", 16))
	first := httptest.NewRecorder()
	p.handleRequest(first, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader(body)))
	second := httptest.NewRecorder()
	p.handleRequest(second, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader(body)))
	var result providerResult
	if err := json.Unmarshal(second.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Reason != "rate_limited" || result.ProbeID != strings.Repeat("aa", 16) {
		t.Fatalf("rate-limited result = %+v, want correlated rate_limited result", result)
	}
}

func TestProviderBusyResultRetainsProbeID(t *testing.T) {
	controllerPub, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPrivate})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(p.inbound); i++ {
		p.inbound <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(p.inbound); i++ {
			<-p.inbound
		}
	}()
	probeID := strings.Repeat("bb", 16)
	recorder := httptest.NewRecorder()
	p.handleRequest(recorder, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader(signedAdmissionRequest(t, controllerPrivate, probeID))))
	var result providerResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Reason != "busy" || result.ProbeID != "" {
		t.Fatalf("busy result = %+v, want generic pre-auth busy result", result)
	}
}

func TestProviderFullReplayCachePreservesLiveFence(t *testing.T) {
	controllerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPrivate, MaxReplayEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first := &providerRequest{Schema: providerRequestSchema, ProbeID: "first", TimestampUnix: now.Unix()}
	second := &providerRequest{Schema: providerRequestSchema, ProbeID: "second", TimestampUnix: now.Unix()}
	if reason := p.admitReplay(first, now); reason != "" {
		t.Fatalf("first replay admission = %q", reason)
	}
	if reason := p.admitReplay(second, now); reason != "busy" {
		t.Fatalf("full replay admission = %q, want busy", reason)
	}
	if _, ok := p.replay[replayKey(first)]; !ok {
		t.Fatal("full replay admission evicted the live first fence")
	}
}

// R16 RED: unauthenticated ingress must not consume the authenticated global
// execution budget that protects trusted Controller requests.
func TestR16UnsignedRequestsDoNotConsumeAuthenticatedProviderBudget(t *testing.T) {
	controllerPub, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPrivate, MaxRequests: 1})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := httptest.NewRecorder()
	p.handleRequest(unsigned, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader([]byte(`{"probe_id":"bad"}`))))
	valid := httptest.NewRecorder()
	p.handleRequest(valid, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader(signedAdmissionRequest(t, controllerPrivate, strings.Repeat("cc", 16)))))
	var result providerResult
	if err := json.Unmarshal(valid.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Reason == "rate_limited" {
		t.Fatalf("authenticated request was starved by unsigned traffic: %+v", result)
	}
	if result.ProbeID != strings.Repeat("cc", 16) {
		t.Fatalf("authenticated result probe id = %q, want correlated id", result.ProbeID)
	}
}

// R16 RED: the cheap pre-auth concurrency bound must run before signature
// verification, so an attacker cannot make every worker perform crypto/body
// work while the bounded ingress queue is full.
func TestR16PreAuthConcurrencyPrecedesSignatureVerification(t *testing.T) {
	controllerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPrivate, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(p.inbound); i++ {
		p.inbound <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(p.inbound); i++ {
			<-p.inbound
		}
	}()
	recorder := httptest.NewRecorder()
	p.handleRequest(recorder, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader([]byte(`{"probe_id":"unsigned"}`))))
	var result providerResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Reason != "busy" || result.ProbeID != "" {
		t.Fatalf("pre-auth saturation result = %+v, want generic busy", result)
	}
}

// R16 RED: ProviderConfig.MaxRequestBytes must be the actual HTTP body cap;
// the protocol maximum is not a substitute for the configured deployment
// budget.
func TestR16ProviderEnforcesConfiguredMaxRequestBytes(t *testing.T) {
	controllerPub, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := signedAdmissionRequest(t, controllerPrivate, strings.Repeat("dd", 16))
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPrivate, MaxRequestBytes: int64(len(body) - 1)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	p.handleRequest(recorder, httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader(body)))
	var result providerResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Reason != "bad_request" || result.ProbeID != "" {
		t.Fatalf("oversized request result = %+v, want generic bad_request", result)
	}
}
