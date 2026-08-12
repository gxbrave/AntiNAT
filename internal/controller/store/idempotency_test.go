package store_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// RED 3a: the same idempotency key + same request hash replays the stored
// response instead of re-executing.
func TestIdempotencyReplaysSameHash(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	rec := store.IdempotencyRecord{
		Key: "key-12345678", Route: "POST /api/v1/forwards",
		Principal: "admin", RequestHash: "hash-a",
		ResponseStatus: 201, ResponseBody: `{"id":"fwd-1"}`,
	}

	_, replayed, err := s.StoreIdempotency(rec)
	if err != nil {
		t.Fatalf("first StoreIdempotency: %v", err)
	}
	if replayed {
		t.Fatal("first store reported a replay")
	}

	stored, replayed, err := s.StoreIdempotency(rec)
	if err != nil {
		t.Fatalf("replay StoreIdempotency: %v", err)
	}
	if !replayed {
		t.Fatal("same key + same hash did not replay")
	}
	if stored.ResponseStatus != 201 || stored.ResponseBody != `{"id":"fwd-1"}` {
		t.Fatalf("replayed response = %d %q, want stored 201 body", stored.ResponseStatus, stored.ResponseBody)
	}
}

// RED 3b: the same key with a different request hash is a conflict and the
// stored response is left untouched.
func TestIdempotencyConflictsOnDifferentHash(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	first := store.IdempotencyRecord{
		Key: "key-12345678", Route: "POST /api/v1/forwards",
		Principal: "admin", RequestHash: "hash-a",
		ResponseStatus: 201, ResponseBody: `{"id":"fwd-1"}`,
	}
	if _, _, err := s.StoreIdempotency(first); err != nil {
		t.Fatalf("first store: %v", err)
	}

	conflict := first
	conflict.RequestHash = "hash-b"
	if _, _, err := s.StoreIdempotency(conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different hash error = %v, want ErrIdempotencyConflict", err)
	}

	got, err := s.GetIdempotency(first.Key)
	if err != nil {
		t.Fatalf("GetIdempotency: %v", err)
	}
	if got.RequestHash != "hash-a" || got.ResponseBody != `{"id":"fwd-1"}` {
		t.Fatalf("conflicting store mutated the row: %+v", got)
	}
}

// RED 3c: an expired key may be reused by a new request, and the expiry is
// recorded as a durable admin event (docs/error-codes.md §4).
func TestIdempotencyExpiredKeyCanBeReused(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	expired := store.IdempotencyRecord{
		Key: "key-12345678", Route: "POST /api/v1/forwards",
		Principal: "admin", RequestHash: "hash-a",
		ResponseStatus: 201, ResponseBody: `{"id":"fwd-1"}`,
		ExpiresAt: 1, // long past
	}
	if _, _, err := s.StoreIdempotency(expired); err != nil {
		t.Fatalf("store expired: %v", err)
	}

	renewed := expired
	renewed.RequestHash = "hash-b"
	renewed.ResponseBody = `{"id":"fwd-2"}`
	renewed.ExpiresAt = time.Now().Add(store.IdempotencyKeyTTL).Unix()
	_, replayed, err := s.StoreIdempotency(renewed)
	if err != nil {
		t.Fatalf("reuse of expired key: %v", err)
	}
	if replayed {
		t.Fatal("expired key reuse reported a replay")
	}
	got, err := s.GetIdempotency(renewed.Key)
	if err != nil {
		t.Fatalf("GetIdempotency after reuse: %v", err)
	}
	if got.RequestHash != "hash-b" {
		t.Fatalf("reused row hash = %q, want hash-b", got.RequestHash)
	}

	events, err := s.AdminEventsAfter(0, 10)
	if err != nil {
		t.Fatalf("AdminEventsAfter: %v", err)
	}
	if len(events) != 1 || events[0].EventType != "IDEMPOTENCY_KEY_EXPIRED" {
		t.Fatalf("expiry audit events = %+v, want one IDEMPOTENCY_KEY_EXPIRED", events)
	}
}

// RED 3d: admin events are durable and monotonically ordered; the SSE cursor
// (Last-Event-ID) survives a full store restart.
func TestAdminEventsCursorSurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id1, err := s.AppendAdminEvent("NODE_CREATED", `{"id":"n1"}`)
	if err != nil {
		t.Fatalf("AppendAdminEvent 1: %v", err)
	}
	id2, err := s.AppendAdminEvent("NODE_DELETED", `{"id":"n1"}`)
	if err != nil {
		t.Fatalf("AppendAdminEvent 2: %v", err)
	}
	if id1 >= id2 {
		t.Fatalf("event ids not monotonic: %d >= %d", id1, id2)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	last, err := s2.LastAdminEventID()
	if err != nil {
		t.Fatalf("LastAdminEventID: %v", err)
	}
	if last != id2 {
		t.Fatalf("LastAdminEventID = %d, want %d", last, id2)
	}

	after, err := s2.AdminEventsAfter(id1, 10)
	if err != nil {
		t.Fatalf("AdminEventsAfter(id1): %v", err)
	}
	if len(after) != 1 || after[0].ID != id2 || after[0].EventType != "NODE_DELETED" {
		t.Fatalf("resumed events = %+v, want exactly [%d NODE_DELETED]", after, id2)
	}

	all, err := s2.AdminEventsAfter(0, 10)
	if err != nil {
		t.Fatalf("AdminEventsAfter(0): %v", err)
	}
	if len(all) != 2 || all[0].ID != id1 || all[1].ID != id2 {
		t.Fatalf("full replay after restart = %+v, want [id1 id2] in order", all)
	}
}
