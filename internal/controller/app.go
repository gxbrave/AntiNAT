// Controller app composition (P10 Story 5).
//
// Composes the controller process from its P06/P08/P10 services: the
// controller store, auth service, signing keyring, challenge manager, the
// agent hub, the probe manager, and the minimal admin web router — all
// served on one HTTP listener with health/readiness and ordered graceful
// shutdown. A startup failure rolls back everything already opened so no
// resource leaks past a failed boot.
package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// Config wires the controller app.
type Config struct {
	// ListenAddress is the controller HTTP listen address (admin API +
	// agent hub). Empty means 127.0.0.1:3111.
	ListenAddress string
	// StorePath is the controller SQLite path.
	StorePath string
	// KeyDir holds the controller signing keyring (0600).
	KeyDir string
	// Clock is the wall clock (deterministic tests).
	Clock func() time.Time
	// AllowPlaintextPublicEnrollment permits enrollment over plaintext HTTP
	// from non-loopback remotes (default false).
	AllowPlaintextPublicEnrollment bool
	// ProviderHTTPClient overrides the probe manager's provider client
	// (tests inject an in-process provider).
	ProviderHTTPClient *http.Client
	// MaxProbeRounds bounds concurrent provider requests (default 16).
	MaxProbeRounds int
}

// App is one composed controller process.
type App struct {
	cfg Config

	store   *store.Store
	auth    *auth.AuthService
	keyring *security.Keyring
	hub     *agenthub.Hub
	probe   *probe.Manager

	ln   net.Listener
	srv  *http.Server
	addr string

	ready atomic.Bool

	closeMu    sync.Mutex
	closed     bool
	closeOrder []string

	watchCancel context.CancelFunc
	watchWG     sync.WaitGroup
}

// New opens every controller resource. Any failure closes what was already
// opened (rollback) and returns the error; the app is not ready.
func New(cfg Config) (*App, error) {
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:3111"
	}
	if cfg.StorePath == "" {
		return nil, errors.New("controller: store path is required")
	}
	if cfg.KeyDir == "" {
		return nil, errors.New("controller: key dir is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.MaxProbeRounds <= 0 {
		cfg.MaxProbeRounds = 16
	}

	a := &App{cfg: cfg}
	// store -> auth -> keyring -> challenges -> hub -> probe -> web router.
	// Every failure path closes in reverse order (rollback).
	st, err := store.Open(cfg.StorePath)
	if err != nil {
		return nil, fmt.Errorf("controller: open store: %w", err)
	}
	a.store = st
	rollback := func(cause error) (*App, error) {
		_ = a.closeResources()
		return nil, cause
	}

	a.auth = auth.NewService(st)

	keyring, err := security.LoadOrCreateKeyring(cfg.KeyDir, 1)
	if err != nil {
		return rollback(fmt.Errorf("controller: keyring: %w", err))
	}
	a.keyring = keyring

	challenges := security.NewChallengeManager(10*time.Minute, 4096)

	// Circular wiring: the hub delivers probe-plane A2C messages to the
	// probe manager (ProbeSink), and the probe manager needs the live
	// session node public keys from the hub. Create the manager first with a
	// lazy key source that reads through the hub variable once it exists.
	var hub *agenthub.Hub
	probeMgr, err := probe.NewManager(probe.ManagerConfig{
		Store:   st,
		Keyring: keyring,
		Clock:   cfg.Clock,
		NodePublicKey: func(nodeID string) (ed25519.PublicKey, bool) {
			if hub == nil {
				return nil, false
			}
			return hub.AgentPublicKey(nodeID)
		},
		HTTPClient:        cfg.ProviderHTTPClient,
		MaxProviderRounds: cfg.MaxProbeRounds,
	})
	if err != nil {
		return rollback(fmt.Errorf("controller: probe manager: %w", err))
	}
	a.probe = probeMgr

	h, err := agenthub.NewHub(agenthub.Config{
		Store:                          st,
		Keyring:                        keyring,
		Challenges:                     challenges,
		Clock:                          cfg.Clock,
		AllowPlaintextPublicEnrollment: cfg.AllowPlaintextPublicEnrollment,
		ProbeSink:                      probeMgr,
	})
	if err != nil {
		return rollback(fmt.Errorf("controller: agent hub: %w", err))
	}
	a.hub = h
	hub = h

	return a, nil
}

// Start binds the listener and serves the composed HTTP surface. On failure
// every opened resource is rolled back and readiness stays false.
func (a *App) Start() error {
	ln, err := net.Listen("tcp", a.cfg.ListenAddress)
	if err != nil {
		_ = a.closeResources()
		return fmt.Errorf("controller: listen %s: %w", a.cfg.ListenAddress, err)
	}
	a.ln = ln
	a.addr = ln.Addr().String()

	admin, err := web.NewRouter(api.RouterConfig{Store: a.store, Auth: a.auth})
	if err != nil {
		_ = a.closeResources()
		return fmt.Errorf("controller: admin router: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/agent/v1/", a.hub.Handler())
	mux.Handle("/", admin)

	a.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		_ = a.srv.Serve(ln)
	}()
	if err := a.probe.Start(context.Background()); err != nil {
		_ = a.closeResources()
		return fmt.Errorf("controller: start probe manager: %w", err)
	}
	// Start the deletion watcher: it completes online-delete operations
	// when the agent's delete result arrives (Story 6 online delete).
	watchCtx, watchCancel := context.WithCancel(context.Background())
	a.watchCancel = watchCancel
	a.watchWG.Add(1)
	go func() {
		defer a.watchWG.Done()
		a.watchDeletions(watchCtx)
	}()
	a.ready.Store(true)
	return nil
}

// watchDeletions polls the control inbox for agent delete results and
// completes the matching forward-deletion operations.
func (a *App) watchDeletions(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.completeFinishedDeletions()
		}
	}
}

// completeFinishedDeletions scans recent operation_complete / delete-ack
// inbox rows for delete-result payloads and completes the operations.
func (a *App) completeFinishedDeletions() {
	rows, err := a.store.ListControlInboxByType("",
		"operation_complete", "desired_result", "forward_delete_ack")
	if err != nil {
		return
	}
	for _, row := range rows {
		var res struct {
			ForwardID           string `json:"forward_id"`
			DeletionOperationID string `json:"deletion_operation_id"`
			Deleted             bool   `json:"deleted"`
		}
		if err := json.Unmarshal([]byte(row.SemanticPayload), &res); err != nil {
			continue
		}
		if !res.Deleted || res.DeletionOperationID == "" {
			continue
		}
		_ = a.store.CompleteForwardDeletionOperation(res.DeletionOperationID)
	}
}

// Addr returns the bound listener address (valid after Start).
func (a *App) Addr() string { return a.addr }

// Ready reports whether the app started successfully and has not shut down.
func (a *App) Ready() bool { return a.ready.Load() }

// Store exposes the controller store (the walking skeleton registers probe
// providers and asserts on probe state through it).
func (a *App) Store() *store.Store { return a.store }

// ProbeManager exposes the probe manager (the walking skeleton arms probes).
func (a *App) ProbeManager() *probe.Manager { return a.probe }

// Hub exposes the agent hub (the walking skeleton pins the controller key).
func (a *App) Hub() *agenthub.Hub { return a.hub }

// ArmProbe creates a probe operation for one forward at its current spec
// revision and enqueues the probe_arm command (Story 1 controller
// operation). The endpoint must equal the agent's actual bind tuple.
func (a *App) ArmProbe(ctx context.Context, nodeID, forwardID, endpoint string) (store.ProbeOperation, error) {
	row, err := a.store.LatestForwardSpec(forwardID)
	if err != nil {
		return store.ProbeOperation{}, fmt.Errorf("controller: arm probe: %w", err)
	}
	var spec protocol.ForwardSpec
	if err := json.Unmarshal([]byte(row.SpecJSON), &spec); err != nil {
		return store.ProbeOperation{}, fmt.Errorf("controller: arm probe spec: %w", err)
	}
	aid := protocol.ActivationID(forwardID, spec.DesiredRevision)
	return a.probe.Arm(ctx, nodeID, forwardID, hex.EncodeToString(aid[:]), endpoint)
}

// Shutdown stops the HTTP server first, then closes the remaining resources
// in reverse dependency order (store last). It is idempotent.
func (a *App) Shutdown(ctx context.Context) error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	a.ready.Store(false)
	if a.watchCancel != nil {
		a.watchCancel()
		a.watchWG.Wait()
	}
	return a.closeResources()
}

// closeResources stops the HTTP server, then closes the store. It records
// the close order for the ordered-shutdown test.
func (a *App) closeResources() error {
	a.closeOrder = nil
	if a.srv != nil {
		a.closeOrder = append(a.closeOrder, "http")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = a.srv.Shutdown(shutCtx)
		cancel()
	}
	if a.ln != nil {
		_ = a.ln.Close()
	}
	if a.probe != nil {
		a.closeOrder = append(a.closeOrder, "probe")
		_ = a.probe.Close()
	}
	if a.store != nil {
		a.closeOrder = append(a.closeOrder, "store")
		_ = a.store.Close()
	}
	return nil
}

// CloseOrder returns the recorded resource close order (test hook).
func (a *App) CloseOrder() []string {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	return append([]string(nil), a.closeOrder...)
}
