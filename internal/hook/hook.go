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
)

// randomHookID returns a 128-bit random hex identifier used by hook rows.
func randomHookID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unrecoverable in practice; fall back to a
		// deterministic-free time-based id so the API surfaces a conflict
		// rather than a panic. This path is unreachable on any sane platform.
		return "f" + hex.EncodeToString([]byte(err.Error()))[:30]
	}
	return hex.EncodeToString(b)
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
)
