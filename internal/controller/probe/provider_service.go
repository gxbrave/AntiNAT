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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
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
	// MaxReplayEntries bounds the TTL replay cache.
	MaxReplayEntries int
	// ReplaySweepInterval controls the cancellable replay-cache sweeper.
	ReplaySweepInterval time.Duration
	// MaxRequestBytes bounds request bodies.
	MaxRequestBytes int64
	// RateWindow and MaxRequests bound HTTP work before execution.
	RateWindow  time.Duration
	MaxRequests int
	// Authenticated admission axes. Limits are checked and charged as one
	// transaction only when a fresh request obtains an outbound-execution slot.
	ControllerMinuteLimit int
	NodeMinuteLimit       int
	EndpointMinuteLimit   int
	DailyBudget           int
	// DialContext is an injectable TCP dial seam. Production uses net.Dialer;
	// tests use it to prove deadline-install failure performs no I/O.
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// Provider is the bounded antinat-probe service.
type Provider struct {
	cfg         ProviderConfig
	slots       chan struct{}
	inbound     chan struct{}
	mu          sync.Mutex
	replay      map[string]replayEntry
	started     time.Time
	requests    int64
	maxReplay   int
	rateStart   time.Time
	rateCount   int
	controllers map[string]int
	nodes       map[string]int
	endpoints   map[string]int
	dailyDate   string
	dailyCount  int
	sweepCancel context.CancelFunc
	sweepWG     sync.WaitGroup
}

type replayEntry struct {
	expires  time.Time
	material [32]byte
	result   *providerResult
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
	if cfg.MaxReplayEntries <= 0 {
		cfg.MaxReplayEntries = 4096
	}
	if cfg.ReplaySweepInterval <= 0 {
		cfg.ReplaySweepInterval = cfg.ReplayWindow / 2
		if cfg.ReplaySweepInterval <= 0 {
			cfg.ReplaySweepInterval = time.Minute
		}
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = protocol.MaxPayloadBytes
	}
	if cfg.RateWindow <= 0 {
		cfg.RateWindow = time.Minute
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 120
	}
	if cfg.ControllerMinuteLimit <= 0 {
		cfg.ControllerMinuteLimit = cfg.MaxRequests
	}
	if cfg.NodeMinuteLimit <= 0 {
		cfg.NodeMinuteLimit = cfg.MaxRequests
	}
	if cfg.EndpointMinuteLimit <= 0 {
		cfg.EndpointMinuteLimit = cfg.MaxRequests
	}
	if cfg.DailyBudget <= 0 {
		cfg.DailyBudget = cfg.MaxRequests * 24 * 60
	}
	now := cfg.Clock()
	return &Provider{
		cfg:         cfg,
		slots:       make(chan struct{}, cfg.MaxConcurrent),
		inbound:     make(chan struct{}, cfg.MaxConcurrent*2),
		replay:      map[string]replayEntry{},
		started:     now,
		maxReplay:   cfg.MaxReplayEntries,
		rateStart:   now,
		controllers: make(map[string]int),
		nodes:       make(map[string]int),
		endpoints:   make(map[string]int),
		dailyDate:   now.UTC().Format("2006-01-02"),
	}, nil
}

// Start launches the context-owned replay-cache sweeper. HTTP handling remains
// usable without Start for focused tests, while production callers can tie the
// cache lifecycle to the provider service context.
func (p *Provider) Start(parent context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sweepCancel != nil {
		return errors.New("probe: provider already started")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	p.sweepCancel = cancel
	p.sweepWG.Add(1)
	go p.replaySweepLoop(ctx)
	return nil
}

// Close cancels the replay-cache sweeper and waits for it to exit.
func (p *Provider) Close() error {
	p.mu.Lock()
	cancel := p.sweepCancel
	p.sweepCancel = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	p.sweepWG.Wait()
	return nil
}

func (p *Provider) replaySweepLoop(ctx context.Context) {
	defer p.sweepWG.Done()
	ticker := time.NewTicker(p.cfg.ReplaySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.SweepReplay(p.cfg.Clock())
		}
	}
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
	StartedUnix int64
	Requests    int64
	ReplayCache int
	Concurrency int
	LastResult  string
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
	now := p.cfg.Clock()
	p.resetAdmissionWindowLocked(now)
	p.rateCount++
	rateLimited := p.rateCount > p.cfg.MaxRequests
	p.mu.Unlock()

	// Read the protocol-sized body once. No field is used for correlation until
	// the complete signed request has passed strict decoding and verification.
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxPayloadBytes+1))
	if readErr != nil {
		p.writeResult(w, providerResult{Accepted: false, Reason: "bad_request"})
		return
	}
	req, err := decodeProviderRequestAt(bytes.NewReader(raw), p.cfg.ControllerPublicKey, now)
	if err != nil {
		// A request returned alongside a semantic error has already passed
		// signature verification, so its id is safe to correlate. Malformed or
		// unsigned input never contributes attacker-controlled identifiers.
		probeID := ""
		if req != nil {
			probeID = req.ProbeID
		}
		if rateLimited {
			p.writeResult(w, providerResult{ProbeID: probeID, Accepted: false, Reason: "rate_limited"})
			return
		}
		if req != nil {
			// Semantic validation errors still belong to an authenticated
			// request. Preserve the legacy bounded replay fence, but do not
			// charge any outbound identity budget because no dial can occur.
			select {
			case p.inbound <- struct{}{}:
				defer func() { <-p.inbound }()
			default:
				p.writeResult(w, providerResult{ProbeID: probeID, Accepted: false, Reason: "busy"})
				return
			}
			if reason := p.admitReplay(req, now); reason != "" {
				p.writeResult(w, providerResult{ProbeID: probeID, Accepted: false, Reason: reason})
				return
			}
		}
		p.writeResult(w, providerResult{ProbeID: probeID, Accepted: false, Reason: providerRequestReason(err)})
		return
	}
	if rateLimited {
		p.writeResult(w, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "rate_limited"})
		return
	}
	select {
	case p.inbound <- struct{}{}:
		defer func() { <-p.inbound }()
	default:
		p.writeResult(w, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "busy"})
		return
	}

	// Reserve execution capacity before consuming the replay key. A request that
	// cannot run must remain retryable and must not poison the cache.
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		p.writeResult(w, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "busy"})
		return
	}
	if reason := p.admitExecution(req, now); reason != "" {
		if reason == "replay" {
			if cached, ok := p.cachedReplayResult(req, now); ok {
				p.writeCachedResult(w, cached)
				return
			}
			reason = "pending"
		}
		p.writeResult(w, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: reason})
		return
	}

	res := p.execute(r.Context(), req)
	res.cacheKey = replayKey(req)
	p.writeResult(w, res)
}

// resetAdmissionWindowLocked advances all minute buckets together. Keeping a
// single epoch for every identity axis prevents an old controller bucket from
// surviving a node/endpoint rollover and gives the maps a bounded lifetime.
func (p *Provider) resetAdmissionWindowLocked(now time.Time) {
	if !now.Before(p.rateStart.Add(p.cfg.RateWindow)) {
		p.rateStart = now
		p.rateCount = 0
		clear(p.controllers)
		clear(p.nodes)
		clear(p.endpoints)
	}
	date := now.UTC().Format("2006-01-02")
	if p.dailyDate == "" {
		p.dailyDate = date
	}
	if date > p.dailyDate {
		p.dailyDate = date
		p.dailyCount = 0
	}
}

// admitExecution authenticates one fresh outbound execution under one mutex.
// Replay/cached requests return before any budget mutation; a denied axis also
// leaves every other axis untouched.
func (p *Provider) admitExecution(req *providerRequest, now time.Time) string {
	canonical, err := req.canonical()
	if err != nil {
		return "bad_request"
	}
	material := sha256.Sum256(canonical)
	endpoint, err := protocol.ValidateEndpoint(req.Endpoint)
	if err != nil {
		return "invalid_endpoint"
	}
	controllerKey := req.ControllerInstance + "\x00" + req.ControllerKeyID
	nodeKey := strings.ToLower(req.NodePublicKeyHash)
	endpointKey := endpoint.String()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetAdmissionWindowLocked(now)
	p.sweepReplayLocked(now)
	replayID := strings.ToLower(req.ProbeID)
	if entry, ok := p.replay[replayID]; ok && now.Before(entry.expires) {
		if entry.material == material {
			return "replay"
		}
		return "conflict"
	}
	if len(p.replay) >= p.maxReplay {
		return "busy"
	}
	if p.controllers[controllerKey] >= p.cfg.ControllerMinuteLimit ||
		p.nodes[nodeKey] >= p.cfg.NodeMinuteLimit ||
		p.endpoints[endpointKey] >= p.cfg.EndpointMinuteLimit ||
		p.dailyCount >= p.cfg.DailyBudget {
		return "rate_limited"
	}
	p.controllers[controllerKey]++
	p.nodes[nodeKey]++
	p.endpoints[endpointKey]++
	p.dailyCount++
	p.replay[replayID] = replayEntry{expires: now.Add(p.cfg.ReplayWindow), material: material}
	return ""
}

// admitReplay consumes a signed request's probe id in the bounded replay
// cache. Identical signed material is a replay; reuse of the id with different
// material is a conflict and must not be treated as harmless duplication.
func (p *Provider) admitReplay(req *providerRequest, now time.Time) string {
	canonical, err := req.canonical()
	if err != nil {
		return "bad_request"
	}
	material := sha256.Sum256(canonical)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepReplayLocked(now)
	replayID := strings.ToLower(req.ProbeID)
	if entry, ok := p.replay[replayID]; ok && now.Before(entry.expires) {
		if entry.material == material {
			return "replay"
		}
		return "conflict"
	}
	if len(p.replay) >= p.maxReplay {
		// Never evict a live fence to admit new work: doing so would reopen an
		// in-window probe id. The caller can retry after the replay window sweep.
		return "busy"
	}
	p.replay[replayID] = replayEntry{expires: now.Add(p.cfg.ReplayWindow), material: material}
	return ""
}

func replayKey(req *providerRequest) string {
	return strings.ToLower(req.ProbeID)
}

func (p *Provider) cachedReplayResult(req *providerRequest, now time.Time) (providerResult, bool) {
	key := replayKey(req)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepReplayLocked(now)
	entry, ok := p.replay[key]
	if !ok || entry.result == nil || !now.Before(entry.expires) {
		return providerResult{}, false
	}
	return *entry.result, true
}

// SweepReplay removes entries at or beyond their expiry boundary and returns
// the number removed. The explicit time argument makes replay retention
// deterministic in tests and is also used by the background sweeper.
func (p *Provider) SweepReplay(now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sweepReplayLocked(now)
}

func (p *Provider) sweepReplayLocked(now time.Time) int {
	removed := 0
	for id, entry := range p.replay {
		if !now.Before(entry.expires) {
			delete(p.replay, id)
			removed++
		}
	}
	return removed
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
	if digest, err := hex.DecodeString(req.ArmDigest); err != nil || len(digest) != len(digest32) {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "bad_request"}
	} else {
		copy(digest32[:], digest)
	}
	var probeID, providerID, activation, opaque [16]byte
	for i, value := range []string{req.ProbeID, req.ProviderID, req.Activation, req.ExpiryOpaque} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 16 {
			return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "bad_request"}
		}
		switch i {
		case 0:
			copy(probeID[:], b)
		case 1:
			copy(providerID[:], b)
		case 2:
			copy(activation[:], b)
		case 3:
			copy(opaque[:], b)
		}
	}
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

	sourceBytes, err := hex.DecodeString(req.ExpectedSourceIP)
	if err != nil || len(sourceBytes) != 4 || net.IP(sourceBytes).IsUnspecified() {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "invalid_source"}
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	// The source bind is part of the provider policy. The default seam uses a
	// net.Dialer with this LocalAddr; injected test dialers own that detail.
	dialContext := p.cfg.DialContext
	if p.cfg.DialContext == nil {
		dialer := net.Dialer{Timeout: p.cfg.DialTimeout, LocalAddr: &net.TCPAddr{IP: net.IP(sourceBytes)}}
		dialContext = dialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp4", req.Endpoint)
	if err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "unreachable"}
	}
	defer conn.Close()
	if err := conn.SetDeadline(p.cfg.Clock().Add(p.cfg.ExchangeTimeout)); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "deadline_failed"}
	}

	wan1 := append(frame.Canonical(), frame.Signature...)
	if _, err := conn.Write(wan1); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "send_failed"}
	}
	ackBuf := make([]byte, 4+32+32+64)
	if _, err := readFullConn(conn, ackBuf); err != nil {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "no_ack"}
	}
	nodePub, err := hex.DecodeString(req.NodePublicKey)
	if err != nil || len(nodePub) != ed25519.PublicKeySize {
		return providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "bad_request"}
	}
	ack, err := protocol.ParseProbeACK(ackBuf, ed25519.PublicKey(nodePub))
	if err != nil || !verifyProbeACKBinding(frame, ack) {
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

// verifyProbeACKBinding keeps signature validity separate from semantic
// binding: a valid node signature over another operation is not evidence for
// this WAN1 exchange.
func verifyProbeACKBinding(frame protocol.ProviderFrame, ack protocol.ProbeACK) bool {
	return ack.ArmDigest == frame.ArmDigest && ack.ChallengeHash == frame.ChallengeHash()
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

// writeResult signs and writes a provider response using the configured clock.
func (p *Provider) writeResult(w http.ResponseWriter, res providerResult) {
	res.Schema = providerResultSchema
	res.TimestampUnix = p.cfg.Clock().Unix()
	res.Signature = hex.EncodeToString(ed25519.Sign(p.cfg.ProviderPrivateKey, res.canonical()))
	if res.cacheKey != "" {
		p.mu.Lock()
		if entry, ok := p.replay[res.cacheKey]; ok {
			cached := res
			entry.result = &cached
			p.replay[res.cacheKey] = entry
		}
		p.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (p *Provider) writeCachedResult(w http.ResponseWriter, res providerResult) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
