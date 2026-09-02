package hook

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Service is the API-facing hook facade: webhook definitions, encrypted hook
// secrets (metadata only — values are never returned), delivery retry/event
// enqueue, and the async at-least-once dispatcher. The API layer consumes this
// type instead of poking at the hook store directly.
type Service struct {
	Store      *Store
	Keys       *SecretKeystore
	Broker     *Broker
	Dispatcher *Dispatcher
}

// ServiceConfig wires the hook service. DBPath must be the controller store's
// SQLite file (already migrated); KeyPath is the AES-256-GCM key file.
type ServiceConfig struct {
	DBPath   string
	KeyPath  string
	Sender   Sender
	Runner   ScriptRunner
	Interval time.Duration
	Batch    int
}

// NewService opens the hook store and key store and builds the dispatcher with
// the production delivery preparer (broker + optional script runner). A nil
// Sender is allowed (the pump fails closed until real wiring); production
// passes the SSRF-safe client. A nil Runner keeps plain and secret-signable
// webhook deliveries working while scripted deliveries fail closed (webhook-
// only); production passes the OS-isolated runner.
func NewService(cfg ServiceConfig) (*Service, error) {
	st, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	keys, err := LoadOrCreateSecretKey(cfg.KeyPath)
	if err != nil {
		st.Close()
		return nil, err
	}
	broker := NewBroker(st, keys)
	preparer := NewDeliveryPreparer(st, broker, cfg.Runner)
	dispatcher := NewDispatcher(st, cfg.Sender, preparer, DispatcherConfig{
		Interval: cfg.Interval,
		Batch:    cfg.Batch,
	})
	return &Service{Store: st, Keys: keys, Broker: broker, Dispatcher: dispatcher}, nil
}

// Close closes the hook store pool (the controller store owns the database
// lifecycle; the dispatcher is stopped by cancelling its Run context).
func (s *Service) Close() error {
	if s == nil || s.Store == nil {
		return nil
	}
	return s.Store.Close()
}

// SetClock injects a deterministic clock (tests).
func (s *Service) SetClock(clock func() time.Time) {
	if s != nil && s.Store != nil {
		s.Store.SetClock(clock)
	}
}

// --- webhook definitions (api/openapi.yaml HookDefinition) ---

func (s *Service) ListDefinitions() ([]Definition, error) {
	return s.Store.ListDefinitions()
}

func (s *Service) CreateDefinition(name, kind, rawURL string) (Definition, error) {
	if err := validateHookName(name); err != nil {
		return Definition{}, err
	}
	if kind != KindWebhook {
		return Definition{}, fmt.Errorf("%w: kind must be %q", ErrInvalid, KindWebhook)
	}
	if err := validateHookURL(rawURL); err != nil {
		return Definition{}, err
	}
	return s.Store.CreateDefinition(strings.TrimSpace(name), kind, strings.TrimSpace(rawURL))
}

func (s *Service) UpdateDefinition(id string, name, url *string, expectedRev uint64) (Definition, error) {
	if name != nil {
		if err := validateHookName(*name); err != nil {
			return Definition{}, err
		}
		trimmed := strings.TrimSpace(*name)
		name = &trimmed
	}
	if url != nil {
		if err := validateHookURL(*url); err != nil {
			return Definition{}, err
		}
		trimmed := strings.TrimSpace(*url)
		url = &trimmed
	}
	return s.Store.UpdateDefinition(id, name, url, expectedRev)
}

func (s *Service) DeleteDefinition(id string, expectedRev uint64) error {
	return s.Store.DeleteDefinition(id, expectedRev)
}

// --- hook secrets (api/openapi.yaml HookSecret; metadata only) ---

func (s *Service) ListSecrets() ([]Secret, error) {
	return s.Store.ListSecrets()
}

// CreateSecret encrypts the value at rest and returns metadata only. The
// plaintext value is never stored unencrypted and never returned.
func (s *Service) CreateSecret(secretID, algorithm, value string) (Secret, error) {
	secretID = strings.TrimSpace(secretID)
	if secretID == "" {
		return Secret{}, fmt.Errorf("%w: secret_id is required", ErrInvalid)
	}
	if len(secretID) > 128 {
		return Secret{}, fmt.Errorf("%w: secret_id is too long", ErrInvalid)
	}
	if value == "" {
		return Secret{}, fmt.Errorf("%w: secret value is required", ErrInvalid)
	}
	if !ValidateAlgorithm(strings.TrimSpace(algorithm)) {
		return Secret{}, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalid, algorithm)
	}
	blob, keyID, err := s.Keys.Encrypt([]byte(value))
	if err != nil {
		return Secret{}, err
	}
	return s.Store.CreateSecret(secretID, strings.TrimSpace(algorithm), blob, keyID)
}

func (s *Service) DeleteSecret(id string, expectedRev uint64) error {
	return s.Store.DeleteSecret(id, expectedRev)
}

// --- delivery queue (event hooks) ---

// EnqueueLifecycleEvent queues one durable lifecycle event for delivery. The
// caller must already have durably recorded/verified the underlying state
// change it describes (forward deletion, probe result, etc.); the queue never
// fabricates the event.
//
// This is the PUBLIC enqueue seam (P2-3 integration handoff): the dispatcher
// pump, at-least-once guarantee, and decommission-drop semantics are armed and
// verified here, but no P14/P15 lifecycle file currently calls this method. The
// production lifecycle→webhook wiring (forward-delete durable events; node
// decommission/uninstall bounded best-effort drop) is an explicit P17/P19
// composition point that consumes this seam. No P14/P15 lifecycle file was
// modified to preserve ownership.
func (s *Service) EnqueueLifecycleEvent(evt Event) (Delivery, error) {
	return s.Store.EnqueueEvent(evt)
}

// RetryDelivery requeues a FAILED/DLQED delivery as PENDING in one transaction
// with a fresh attempt budget and a durable audit.
func (s *Service) RetryDelivery(id string) (Delivery, error) {
	return s.Store.RetryDelivery(id)
}

// MarkDecommissioned bounds delivery best-effort for a node: deliveries
// targeting the node are dropped after the deadline (dispatcher applies the
// drop; this just arms the deadline). The arming and its audit share one
// transaction.
func (s *Service) MarkDecommissioned(nodeID string, deadline int64) error {
	return s.Store.MarkDecommissioned(nodeID, deadline)
}

// --- INTERNAL capability wiring (P1-2; never part of the frozen API surface) ---

// BindSecretToHook durably binds a secret to a hook. The broker refuses to
// sign for an unbound (hook_id, secret_id) pair (ErrSecretNotBoundToHook).
func (s *Service) BindSecretToHook(hookID, secretID string) error {
	return s.Store.BindSecretToHook(hookID, secretID)
}

// SetSecretSignatureBudget sets the durable total-signature cap for a secret
// (fail closed when 0). The broker reserves one unit per issued signature.
func (s *Service) SetSecretSignatureBudget(secretID string, budget int64) error {
	return s.Store.SetSecretSignatureBudget(secretID, budget)
}

// SetHookParamsAllowlist replaces the per-hook signing param allowlist used by
// query-placement signing (absent allowlist -> ErrNoParamsAllowlist).
func (s *Service) SetHookParamsAllowlist(hookID string, allowed []string) error {
	return s.Store.SetHookParamsAllowlist(hookID, allowed)
}

func (s *Service) ListDeliveries(limit int) ([]Delivery, error) {
	return s.Store.ListDeliveries(limit)
}

// PumpOnce runs one dispatcher batch (test/operational hook).
func (s *Service) PumpOnce() int {
	if s.Dispatcher == nil {
		return 0
	}
	return s.Dispatcher.PumpOnce()
}

// Run starts the dispatcher until the context is cancelled.
func (s *Service) Run(ctx context.Context) {
	if s.Dispatcher != nil {
		s.Dispatcher.Run(ctx)
	}
}

func validateHookName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return fmt.Errorf("%w: name must be 1..128 characters", ErrInvalid)
	}
	return nil
}

func validateHookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid url: %v", ErrInvalid, err)
	}
	// Hook definitions must be HTTPS (P3-12). The production SSRF client
	// (ClientConfig{} in app.go) rejects plain HTTP by default, so allowing an
	// http:// hook definition would let a user create a webhook that can never
	// be delivered.
	if u.Scheme != "https" {
		return fmt.Errorf("%w: url scheme must be https", ErrInvalid)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url must not contain userinfo", ErrInvalid)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: url host is required", ErrInvalid)
	}
	host := u.Hostname()
	if strings.Contains(host, "%") {
		return fmt.Errorf("%w: url zone identifiers are rejected", ErrInvalid)
	}
	if strings.HasSuffix(host, ".") {
		return fmt.Errorf("%w: url trailing-dot host is ambiguous", ErrInvalid)
	}
	// P2-1: a hook URL must not carry a query string or fragment. buildURL for a
	// SIGNED delivery renders scheme/host/port/path ONLY (pathOf takes u.Path),
	// so a query-bearing hook URL would be silently stripped for signed
	// deliveries while unsigned deliveries preserved it — an inconsistent,
	// fail-open surface. We reject such URLs outright here (stricter than the
	// frozen openapi `format: uri`, which stays unchanged), and the dispatcher
	// + broker re-assert the same rule defense-in-depth at dispatch time.
	if err := rejectURLQueryFragment(u); err != nil {
		return err
	}
	return nil
}

// rejectURLQueryFragment refuses a parsed hook URL that carries a query string
// or fragment (shared by definition validation, the delivery preparer and the
// broker's endpoint re-derivation so a query-bearing hook definition can never
// reach dispatch even if it bypassed service validation at the store level).
func rejectURLQueryFragment(u *url.URL) error {
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%w: url must not carry a query string", ErrInvalid)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("%w: url must not carry a fragment", ErrInvalid)
	}
	return nil
}
