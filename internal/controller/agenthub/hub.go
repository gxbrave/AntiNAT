// Package agenthub implements the Controller-side Agent control plane: the
// enrollment HTTP surface (challenge/request/result transcript) and the
// bounded WebSocket control session (P08).
//
// The hub is transport-only: it validates signatures, enforces epoch/session
// fencing, drives the controller outbox/inbox journals, and enforces the
// frozen message dedup rules. It owns no data-plane logic.
package agenthub

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// Config wires the hub to its dependencies.
type Config struct {
	Store      *store.Store
	Keyring    *security.Keyring
	Challenges *security.ChallengeManager

	// Clock is the wall clock for expiry/audit timestamps (deterministic
	// tests); defaults to time.Now.
	Clock func() time.Time

	// AllowPlaintextPublicEnrollment permits enrollment over plaintext HTTP
	// from non-loopback remotes. Default false: public plaintext enrollment
	// is refused (v0.8 §6.2 token safety + Story 6 transport boundary).
	AllowPlaintextPublicEnrollment bool

	// EnrollResultTTL bounds the signed EnrollResult expiry; default 24h.
	EnrollResultTTL time.Duration

	// MaxEnrollBodyBytes bounds enrollment request bodies (resource bound).
	MaxEnrollBodyBytes int64

	// ControlWriteTimeout bounds controller-generated receipt writes.
	ControlWriteTimeout time.Duration

	// ProbeSink is the P10-declared consumption interface: the controller
	// probe manager registers here to receive durable probe-plane A2C
	// messages (probe_armed, probe_ingress_receipt, probe_result). The hub
	// stays transport-only; it records the message durably and hands the
	// payload to the sink. A nil sink is valid (probe messages are still
	// durably recorded).
	ProbeSink ProbeSink
}

// ProbeSink consumes durably recorded probe-plane A2C messages. P08 declares
// that P10 consumes the control channel via interfaces; this is that
// interface. Implementations must be safe for concurrent calls.
type ProbeSink interface {
	// HandleProbeMessage is invoked after the hub durably recorded an A2C
	// probe-plane message. messageType is one of probe_armed,
	// probe_ingress_receipt, or probe_result; payload is the raw envelope
	// payload (RDY1 frame bytes for probe_armed, RCT1 frame bytes for
	// probe_ingress_receipt, JSON for probe_result).
	HandleProbeMessage(nodeID, messageType string, payload []byte) error
}

// ActivationStatusSink consumes durable agent evidence-loss snapshots. It is
// optional so older non-P10 sinks remain source-compatible.
type ActivationStatusSink interface {
	HandleActivationStatus(nodeID string, payload []byte) error
}

// Hub is the Controller-side Agent hub.
type Hub struct {
	store      *store.Store
	keyring    *security.Keyring
	challenges *security.ChallengeManager
	clock      func() time.Time
	cfg        Config
	sink       ProbeSink

	sessionsMu sync.Mutex
	sessions   map[string]*ControlSession
	closed     bool
}

// NewHub validates the configuration and builds the hub.
func NewHub(cfg Config) (*Hub, error) {
	if cfg.Store == nil {
		return nil, errors.New("agenthub: store is required")
	}
	if cfg.Keyring == nil {
		return nil, errors.New("agenthub: keyring is required")
	}
	if cfg.Challenges == nil {
		return nil, errors.New("agenthub: challenge manager is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.EnrollResultTTL <= 0 {
		cfg.EnrollResultTTL = 24 * time.Hour
	}
	if cfg.MaxEnrollBodyBytes <= 0 {
		cfg.MaxEnrollBodyBytes = 4096
	}
	if cfg.ControlWriteTimeout <= 0 {
		cfg.ControlWriteTimeout = 5 * time.Second
	}
	return &Hub{store: cfg.Store, keyring: cfg.Keyring, challenges: cfg.Challenges, clock: cfg.Clock, cfg: cfg, sink: cfg.ProbeSink, sessions: make(map[string]*ControlSession)}, nil
}

// Close terminates every active control session. The operation is idempotent;
// callers use it after stopping the HTTP server and before closing the store.
func (h *Hub) Close() error {
	h.sessionsMu.Lock()
	if h.closed {
		h.sessionsMu.Unlock()
		return nil
	}
	h.closed = true
	sessions := make([]*ControlSession, 0, len(h.sessions))
	for _, session := range h.sessions {
		sessions = append(sessions, session)
	}
	h.sessionsMu.Unlock()

	for _, session := range sessions {
		session.close()
	}
	for _, session := range sessions {
		session.wait()
	}
	return nil
}

// Handler returns the hub's HTTP surface:
//
//	POST /agent/v1/enroll/challenge   body: raw node id (<= 16 bytes)
//	POST /agent/v1/enroll/request     body: raw signed EnrollRequest bytes
//	GET  /agent/v1/control            WebSocket control session
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/enroll/challenge", h.handleEnrollChallenge)
	mux.HandleFunc("/agent/v1/enroll/request", h.handleEnrollRequest)
	mux.HandleFunc("/agent/v1/control", h.handleControl)
	return mux
}

// enrollAllowed reports whether this enrollment request may proceed: plaintext
// public enrollment is refused unless explicitly enabled (Story 6).
func (h *Hub) enrollAllowed(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if h.cfg.AllowPlaintextPublicEnrollment {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false // unparseable remote: fail closed
	}
	return addr.IsLoopback()
}

func (h *Hub) now() int64 { return h.clock().Unix() }

// audit records a durable admin event with a redacted payload.
func (h *Hub) audit(eventType, payload string) {
	if _, err := h.store.AppendAdminEvent(eventType, payload); err != nil {
		// Auditing must never break the control plane; the event log is
		// best-effort on the hub path.
		_ = fmt.Errorf("agenthub: audit %s: %w", eventType, err)
	}
}
