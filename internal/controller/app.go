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

	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
	"github.com/gxbrave/AntiNAT/internal/hook"
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

type appLifecycleState uint8

const (
	appStateNew appLifecycleState = iota
	appStateRunning
	appStateClosing
	appStateClosed
)

// App is one composed controller process.
type App struct {
	cfg Config

	store   *store.Store
	auth    *auth.AuthService
	keyring *security.Keyring
	hub     *agenthub.Hub
	probe   *probe.Manager
	hooks   *hook.Service

	ln   net.Listener
	srv  *http.Server
	addr string

	ready atomic.Bool

	// lifecycleMu serializes the complete Start/Shutdown transitions, including
	// watcher Wait/Add and rollback. This prevents a concurrent Shutdown from
	// observing a half-started app or a later Start from reopening closed deps.
	lifecycleMu sync.Mutex
	state       appLifecycleState
	closeOrder  []string

	watchCancel context.CancelFunc
	watchWG     sync.WaitGroup
	hookCancel  context.CancelFunc
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
	// store -> auth -> keyring -> challenges -> hub -> probe -> hooks -> router.
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

	// P16: the hook service owns webhooks/secrets/deliveries. Its store opens
	// its own pool on the same (already migrated) database file; the dispatcher
	// uses the SSRF-safe client as its sender so no outbound webhook can reach
	// a private/loopback address.
	hookSvc, err := hook.NewService(hook.ServiceConfig{
		DBPath:  cfg.StorePath,
		KeyPath: filepath.Join(cfg.KeyDir, "hook-secret.key"),
		Sender:  hook.NewClient(hook.ClientConfig{}),
	})
	if err != nil {
		return rollback(fmt.Errorf("controller: hook service: %w", err))
	}
	a.hooks = hookSvc

	return a, nil
}

// Start binds the listener and serves the composed HTTP surface. On failure
// every opened resource is rolled back and readiness stays false.
func (a *App) Start() error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.state != appStateNew {
		return errors.New("controller: app is not in NEW state")
	}

	fail := func(err error) error {
		a.ready.Store(false)
		a.state = appStateClosing
		if closeErr := a.closeResources(); closeErr != nil {
			a.state = appStateClosing
			return fmt.Errorf("%w (rollback: %v)", err, closeErr)
		}
		a.state = appStateClosed
		return err
	}

	ln, err := net.Listen("tcp", a.cfg.ListenAddress)
	if err != nil {
		return fail(fmt.Errorf("controller: listen %s: %w", a.cfg.ListenAddress, err))
	}
	a.ln = ln
	a.addr = ln.Addr().String()

	// repair-1 H8: compose the canonical durable, bounded SSE stream on the
	// frozen /api/v1/events route (Last-Event-ID replay + secret redaction +
	// bounded subscriber/backpressure) instead of the un-composed local poller.
	// repair-2 P1-A: build through NewSSEHandler so the subscriber gate is
	// initialized during construction (never lazily inside ServeHTTP).
	events := web.NewSSEHandler(a.store, 100*time.Millisecond, 100, 64, 0)
	// repair-1 H3: compose the agent-hub session closer so a force node delete
	// cannot leave an ESTABLISHED session delivering stale commands. P16: hooks
	// composes the hook service (definitions/secrets/deliveries + dispatcher).
	admin, err := web.NewRouter(api.RouterConfig{Store: a.store, Auth: a.auth, SSE: events, CloseNodeSession: a.hub.ForceCloseNodeSession, Hooks: a.hooks})
	if err != nil {
		return fail(fmt.Errorf("controller: admin router: %w", err))
	}

	mux := http.NewServeMux()
	mux.Handle("/agent/v1/", a.hub.Handler())
	mux.Handle("/", admin)

	a.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := a.probe.Start(context.Background()); err != nil {
		return fail(fmt.Errorf("controller: start probe manager: %w", err))
	}
	go func() {
		_ = a.srv.Serve(ln)
	}()

	// Add the watcher while lifecycleMu is held; Shutdown cannot race Wait with
	// this Add operation.
	watchCtx, watchCancel := context.WithCancel(context.Background())
	a.watchCancel = watchCancel
	a.watchWG.Add(2)
	go func() {
		defer a.watchWG.Done()
		a.watchDeletions(watchCtx)
	}()
	go func() {
		defer a.watchWG.Done()
		a.watchNodeDeletions(watchCtx)
	}()

	// P16: run the hook delivery dispatcher (at-least-once pump). It is
	// stopped by cancelling its context during shutdown.
	hookCtx, hookCancel := context.WithCancel(context.Background())
	a.hookCancel = hookCancel
	if a.hooks != nil {
		go a.hooks.Run(hookCtx)
	}
	a.state = appStateRunning
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

// completeFinishedDeletions drains only durably correlated dedicated deletion
// results. Ordinary operation_complete rows remain RECEIVED for their normal
// result consumer; payload shape alone never makes a row a deletion candidate.
func (a *App) completeFinishedDeletions() {
	rows, err := a.store.ListForwardDeletionResultCandidates(500)
	if err != nil {
		return
	}
	for _, row := range rows {
		err := a.store.CompleteForwardDeletionMessage(row.MessageID)
		if errors.Is(err, store.ErrPermanentDeletionResult) {
			// Only an authenticated, durably correlated deletion result whose
			// identity is permanently impossible may be terminalized. An ordinary
			// generic result returns ErrNotFound and remains available elsewhere.
			_ = a.store.RejectControlInbox(row.MessageID)
		}
	}
}

// watchNodeDeletions polls for durable node_decommission_ack results and
// advances the matching node deletion operations (repair-1 H3b).
func (a *App) watchNodeDeletions(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.completeNodeDeletions()
		}
	}
}

// completeNodeDeletions advances every RECEIVED node_decommission_ack that is
// durably correlated to a live node deletion operation. A permanently
// impossible identity is terminalized (NACKed) so it cannot spin; storage
// errors are left RECEIVED for the next poll.
func (a *App) completeNodeDeletions() {
	rows, err := a.store.ListNodeDeletionResults(100)
	if err != nil {
		return
	}
	for _, row := range rows {
		if _, _, err := a.store.CompleteNodeDeletionResult(row.MessageID); err != nil {
			if errors.Is(err, store.ErrPermanentDeletionResult) {
				_ = a.store.RejectControlInbox(row.MessageID)
			}
		}
	}
}

// Addr returns the bound listener address (valid after Start).
func (a *App) Addr() string {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.addr
}

// Ready reports whether the app started successfully and has not shut down.
func (a *App) Ready() bool { return a.ready.Load() }

// Store exposes the controller store (the walking skeleton registers probe
// providers and asserts on probe state through it).
func (a *App) Store() *store.Store { return a.store }

// ProbeManager exposes the probe manager (the walking skeleton arms probes).
func (a *App) ProbeManager() *probe.Manager { return a.probe }

// Hub exposes the agent hub (the walking skeleton pins the controller key).
func (a *App) Hub() *agenthub.Hub { return a.hub }

// Hooks exposes the hook service (P16 webhook definitions/secrets/deliveries).
func (a *App) Hooks() *hook.Service { return a.hooks }

// ArmProbe creates a probe operation for one forward at its current spec
// revision and enqueues the probe_arm command (Story 1 controller
// operation). The endpoint must equal the agent's actual bind tuple.
func (a *App) ArmProbe(ctx context.Context, nodeID, forwardID, endpoint string) (store.ProbeOperation, error) {
	row, err := a.store.LatestForwardSpec(forwardID)
	if err != nil {
		return store.ProbeOperation{}, fmt.Errorf("controller: arm probe: %w", err)
	}
	var spec protocol.ForwardSpec
	if err := protocol.DecodeStrictJSONInto([]byte(row.SpecJSON), &spec); err != nil {
		return store.ProbeOperation{}, fmt.Errorf("controller: arm probe spec: %w", err)
	}
	aid := protocol.ActivationID(forwardID, spec.DesiredRevision)
	return a.probe.Arm(ctx, nodeID, forwardID, hex.EncodeToString(aid[:]), endpoint)
}

// Shutdown stops the HTTP server first, then closes the remaining resources
// in reverse dependency order (store last). It is idempotent and bounded by
// ctx while joining the watcher and AgentHub handshake/session drain.
func (a *App) Shutdown(ctx context.Context) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if a.state == appStateClosed {
		return nil
	}
	if a.state != appStateNew && a.state != appStateRunning && a.state != appStateClosing {
		return errors.New("controller: invalid lifecycle state")
	}
	a.state = appStateClosing
	a.ready.Store(false)
	if a.watchCancel != nil {
		a.watchCancel()
	}
	if a.hookCancel != nil {
		a.hookCancel()
	}
	if err := waitControllerGroup(ctx, &a.watchWG); err != nil {
		// Keep CLOSING and retain the cancellation handle so a later call can
		// retry the same close operation after the caller's deadline expires.
		return fmt.Errorf("controller: wait for watcher: %w", err)
	}
	a.watchCancel = nil
	if err := a.closeResourcesContext(ctx); err != nil {
		// A failed close is retryable; never advertise CLOSED while a resource
		// may still be usable.
		return err
	}
	a.state = appStateClosed
	return nil
}

func waitControllerGroup(ctx context.Context, wg *sync.WaitGroup) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeResources stops the HTTP server, then closes the store. It records
// the close order for the ordered-shutdown test.
func (a *App) closeResources() error {
	return a.closeResourcesContext(context.Background())
}

func (a *App) closeResourcesContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	a.closeOrder = nil
	var firstErr error
	if a.srv != nil {
		a.closeOrder = append(a.closeOrder, "http")
		if err := a.srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if a.ln != nil {
		if err := a.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && firstErr == nil {
			firstErr = err
		}
	}
	if a.hub != nil {
		a.closeOrder = append(a.closeOrder, "hub")
		if err := a.hub.CloseContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if a.probe != nil {
		a.closeOrder = append(a.closeOrder, "probe")
		if err := a.probe.CloseContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if a.hooks != nil {
		a.closeOrder = append(a.closeOrder, "hooks")
		if err := a.hooks.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Never close the store while an upstream resource (especially the probe
	// manager's manager-owned finalizer) may still be using it. A caller whose
	// context expired can retry Shutdown and join the same close cycle first.
	if firstErr != nil {
		return firstErr
	}
	if a.store != nil {
		a.closeOrder = append(a.closeOrder, "store")
		if err := a.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// CloseOrder returns the recorded resource close order (test hook).
func (a *App) CloseOrder() []string {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return append([]string(nil), a.closeOrder...)
}
