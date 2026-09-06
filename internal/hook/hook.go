// Package hook implements the P16 hook subsystem: webhook definitions,
// encrypted hook secrets, the durable at-least-once delivery queue, the
// SSRF-safe webhook transport, the capability-bounded request-signing broker,
// the isolated JavaScript runner, and the Linux/Windows OS-isolation gate.
//
// The hook subsystem owns the hook_definitions / hook_secrets /
// hook_deliveries tables created by migrations/0010_hooks.sql and talks to
// the shared controller SQLite file directly (the store applies migrations;
// the hook store reuses the same WAL-backed database file so one process owns
// one database). The API surface is fixed by api/openapi.yaml §/api/v1/hooks/*
// and §/api/v1/hook-deliveries/*; this package is exclusively webhook (no
// local-script / provider adapters in v1).
package hook

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// randomHookID returns a 128-bit random hex identifier used by hook rows. It
// FAILS CLOSED on crypto/rand failure instead of returning a degenerate stable
// id that would later surface as unique-constraint conflicts (P3-11).
func randomHookID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("hook: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Delivery states (the observable delivery surface, v0.8 §8.1).
const (
	// DeliveryPending waits for its next attempt.
	DeliveryPending = "PENDING"
	// DeliveryInFlight has been claimed by the dispatcher and is being sent.
	DeliveryInFlight = "IN_FLIGHT"
	// DeliveryDelivered is the terminal success state.
	DeliveryDelivered = "DELIVERED"
	// DeliveryFailed is a transient failure scheduled for a retry at the
	// bounded backoff computed in NextAttemptAt.
	DeliveryFailed = "FAILED"
	// DeliveryDLQed is the terminal dead-letter state (max attempts or an
	// explicit queue-full DLQ policy). It is recoverable via the retry API.
	DeliveryDLQed = "DLQED"
	// DeliveryDroppedDecommission is the terminal bounded best-effort state for
	// node decommission/uninstall deliveries: after the decommission deadline
	// the delivery is dropped (never a permanent at-least-once promise).
	DeliveryDroppedDecommission = "DROPPED_DUE_TO_DECOMMISSION"
)

// Hook kinds accepted in v1 (api/openapi.yaml HookDefinition.kind enum).
const (
	KindWebhook = "webhook"
)

// Marker errors returned by the hook store.
var (
	ErrNotFound    = errors.New("hook: record not found")
	ErrConflict    = errors.New("hook: conflict")
	ErrInvalid     = errors.New("hook: invalid argument")
	ErrCASConflict = errors.New("hook: revision CAS conflict")
	ErrQueueFull   = errors.New("hook: delivery queue is full")
	ErrNotMigrated = errors.New("hook: database not migrated to schema version 10")

	// ErrSecretNotBoundToHook refuses a signing intent whose (hook_id,
	// secret_id) pair is not durably bound (P1-2; fail closed so an unbound
	// secret can never be turned into an oracle).
	ErrSecretNotBoundToHook = errors.New("hook: secret is not bound to this hook")

	// ErrNoSignatureBudget refuses a signing intent for a secret with no
	// configured signature budget (0 == disabled, fail closed).
	ErrNoSignatureBudget = errors.New("hook: secret has no configured signature budget")

	// ErrSignatureBudgetExhausted refuses a signing intent past the secret's
	// durable total-signature budget.
	ErrSignatureBudgetExhausted = errors.New("hook: secret signature budget exhausted")

	// ErrEndpointDeviation refuses an intent whose method/scheme/host/port/path
	// deviate from the stored hook definition URL (defense in depth).
	ErrEndpointDeviation = errors.New("hook: signing intent endpoint deviates from the hook definition")

	// ErrNoParamsAllowlist fails query-placement signing closed when the hook
	// has no per-hook params allowlist.
	ErrNoParamsAllowlist = errors.New("hook: query-placement signing requires a per-hook params allowlist")

	// ErrParamNotAllowlisted refuses a script-selected param key that is not in
	// the hook's allowlist.
	ErrParamNotAllowlisted = errors.New("hook: script-selected param is not allowlisted")

	// ErrRunnerPanic is the bounded runner error returned when the in-process
	// interpreter recovers from a panic instead of aborting the controller.
	ErrRunnerPanic = errors.New("hook: isolated runner recovered from a panic")
)
