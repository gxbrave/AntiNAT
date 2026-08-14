// Provider service core (P10 Story 1 GREEN): the operator-owned
// antinat-probe service. It receives controller-signed probe requests,
// generates the provider-hidden challenge, builds and signs the WAN1 frame,
// dials the exact global IPv4 literal, performs the WAN1/ACK1 exchange on the
// same TCP connection, verifies the agent-signed ACK1 against the node
// public key bound in the request, and returns a provider-signed result.
//
// The service is stateless apart from bounded rate/concurrency state and a
// TTL nonce replay cache (v0.8 §5.1: "no persistent business state, but must
// keep TTL nonce replay cache, rate bucket, concurrency state and audit
// summary").
package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ProviderConfig configures the provider service.
type ProviderConfig struct {
	// ControllerPublicKey is the PINNED controller signing key.
	ControllerPublicKey ed25519.PublicKey
	// ProviderPrivateKey signs WAN1 frames and results.
	ProviderPrivateKey ed25519.PrivateKey
	// Clock is the wall clock (deterministic tests).
	Clock func() time.Time
	// DialTimeout bounds the TCP dial to the endpoint.
	DialTimeout time.Duration
	// ExchangeTimeout bounds the WAN1/ACK1 exchange on the connection.
	ExchangeTimeout time.Duration
	// MaxConcurrent bounds simultaneous probe executions.
	MaxConcurrent int
	// ReplayWindow bounds the nonce replay cache.
	ReplayWindow time.Duration
	// MaxRequestBytes bounds request bodies.
	MaxRequestBytes int64
}

// Provider is the bounded antinat-probe service.
type Provider struct {
	cfg      ProviderConfig
	slots    chan struct{}
	mu       sync.Mutex
	replay   map[string]time.Time
	started  time.Time
	requests int64
}

// NewProvider validates config and builds the provider.
func NewProvider(cfg ProviderConfig) (*Provider, error) {
	if len(cfg.ControllerPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("probe: provider requires a pinned controller public key")
	}
	if len(cfg.ProviderPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("probe: provider requires a provider private key")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.ExchangeTimeout <= 0 {
		cfg.ExchangeTimeout = 5 * time.Second
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 8
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = protocol.ProbeReplayWindow
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 8192
	}
	return &Provider{
		cfg:     cfg,
		slots:   make(chan struct{}, cfg.MaxConcurrent),
		replay:  map[string]time.Time{},
		started: cfg.Clock(),
	}, nil
}

// Handler returns the provider HTTP surface:
//
//	POST /probe/v1/request
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe/v1/request", p.handleRequest)
	return mux
}

// Stats is a bounded audit summary.
type Stats struct {
	StartedUnix  int64
	Requests     int64
	ReplayCache  int
	Concurrency  int
	LastResult   string
}

// Stats returns the audit summary.
func (p *Provider) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Stats{
		StartedUnix: p.started.Unix(),
		Requests:    p.requests,
		ReplayCache: len(p.replay),
		Concurrency: len(p.slots),
	}
}

// handleRequest verifies the controller signature, bounds concurrency, and
// executes the WAN1/ACK1 exchange.
func (p *Provider) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.requests++
	p.mu.Unlock()

	body := http.MaxBytesReader(w, r.Body, p.cfg.MaxRequestBytes)
	req, err := decodeProviderRequest(body, p.cfg.ControllerPublicKey)
	if err != nil {
		writeProviderResult(w, p.cfg.ProviderPrivateKey, providerResult{ProbeID: "", Accepted: false, Reason: "bad_request"})
		return
	}

	// TTL nonce replay cache: the same request (by probe id) within the
	// window is a replay and is refused generically.
	p.mu.Lock()
	if expire, ok := p.replay[req.ProbeID]; ok && p.cfg.Clock().Before(expire) {
		p.mu.Unlock()
		writeProviderResult(w, p.cfg.ProviderPrivateKey, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "replay"})
		return
	}
	p.replay[req.ProbeID] = p.cfg.Clock().Add(p.cfg.ReplayWindow)
	p.mu.Unlock()

	// Bounded concurrency.
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		writeProviderResult(w, p.cfg.ProviderPrivateKey, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "busy"})
		return
	}

	res := p.execute(r.Context(), req)
	writeProviderResult(w, p.cfg.ProviderPrivateKey, res)
}

// execute performs the exchange: generate challenge, build WAN1, dial the
// exact endpoint, send WAN1, read ACK1, verify it against the node public
// key bound in the request.
func (p *Provider) execute(ctx context.Context, req *providerRequest) providerResult {
	// Endpoint must be a concrete global IPv4 literal (anti-abuse: reject
	// DNS, private, CGNAT, loopback, link-local, multicast, reserved).
	if _, err := protocol.ValidateEndpoint(req.Endpoint); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "invalid_endpoint"}
	}

	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "challenge_unavailable"}
	}
	var digest32 [32]byte
	copy(digest32[:], mustHexPanic(req.ArmDigest))
	var probeID, providerID, activation, opaque [16]byte
	copy(probeID[:], mustHexPanic(req.ProbeID))
	copy(providerID[:], mustHexPanic(req.ProviderID))
	copy(activation[:], mustHexPanic(req.Activation))
	copy(opaque[:], mustHexPanic(req.ExpiryOpaque))
	frame := protocol.ProviderFrame{
		ArmDigest:    digest32,
		ProbeID:      probeID,
		ProviderID:   providerID,
		Activation:   activation,
		Endpoint:     req.Endpoint,
		ExpiryOpaque: opaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(p.cfg.ProviderPrivateKey, frame.SigningBytes())

	conn, err := net.DialTimeout("tcp4", req.Endpoint, p.cfg.DialTimeout)
	if err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "unreachable"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.cfg.ExchangeTimeout))

	wan1 := append(frame.Canonical(), frame.Signature...)
	if _, err := conn.Write(wan1); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "send_failed"}
	}
	ackBuf := make([]byte, 4+32+32+64)
	if _, err := readFullConn(conn, ackBuf); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "no_ack"}
	}
	nodePub := mustHexPanic(req.NodePublicKey)
	if _, err := protocol.ParseProbeACK(ackBuf, ed25519.PublicKey(nodePub)); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "bad_ack"}
	}
	chash := frame.ChallengeHash()
	return providerResult{
		ProbeID:       req.ProbeID,
		Accepted:      true,
		ChallengeHash: hex.EncodeToString(chash[:]),
		WAN1Frame:     hex.EncodeToString(wan1),
		ACK1Frame:     hex.EncodeToString(ackBuf),
		Reason:        "ack_verified",
	}
}

// readFullConn reads exactly len(buf) bytes or returns an error.
func readFullConn(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// mustHexPanic decodes hex or panics (the request was already verified, so a
// decode failure here is a programming error).
func mustHexPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("probe: malformed hex in verified request: %v", err))
	}
	return b
}
