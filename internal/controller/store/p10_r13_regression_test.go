package store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/migrations"
)

type r13NodeBundler interface {
	CreateNodeBundle(context.Context, Node, IdempotencyRecord) (IdempotencyRecord, bool, error)
}

type r13ProbeDeliveryStore interface {
	QueueProbeOutcome(string, protocol.ProbeOutcome) (string, error)
	ProbeOutcomeDisposition(string) (string, error)
	ListUndeliveredTerminalProbeOperationsPage(int, int64, string) ([]ProbeOperation, error)
	ExpireTerminalProbeDeliveriesBeforeLimit(int64, int) (int, error)
}

func requireR13NodeBundler(t *testing.T, s *Store) r13NodeBundler {
	t.Helper()
	bundler, ok := any(s).(r13NodeBundler)
	if !ok {
		t.Fatal("Store.CreateNodeBundle is missing; node/idempotency commit is not atomic")
	}
	return bundler
}

func requireR13ProbeDeliveryStore(t *testing.T, s *Store) r13ProbeDeliveryStore {
	t.Helper()
	delivery, ok := any(s).(r13ProbeDeliveryStore)
	if !ok {
		t.Fatal("durable bounded terminal probe delivery API is missing")
	}
	return delivery
}

func r13NodeRecord(key, hash string) IdempotencyRecord {
	return IdempotencyRecord{
		Key: key, Route: "/api/v1/nodes", Principal: "admin", RequestHash: hash,
		ResponseStatus: http.StatusCreated,
	}
}

// R13 RED: an idempotency persistence fault rolls back the node side effect.
// The pre-repair API created the node first and discarded StoreIdempotency's
// error, leaving an unreplayable create after a crash or disk fault.
func TestR13NodeAndIdempotencyPersistenceAreAtomic(t *testing.T) {
	s := openTestStore(t)
	bundler := requireR13NodeBundler(t, s)
	if _, err := s.db.Exec(`CREATE TRIGGER r13_fail_idempotency BEFORE INSERT ON api_idempotency_keys BEGIN SELECT RAISE(ABORT, 'r13 injected idempotency fault'); END`); err != nil {
		t.Fatal(err)
	}
	_, _, err := bundler.CreateNodeBundle(context.Background(), Node{ID: "node-fault", Name: "node-fault"}, r13NodeRecord("r13-node-fault", "hash-a"))
	if err == nil {
		t.Fatal("injected idempotency persistence fault was ignored")
	}
	if _, getErr := s.GetNode("node-fault"); !errors.Is(getErr, ErrNodeNotFound) {
		t.Fatalf("node survived failed atomic bundle: %v", getErr)
	}
}

// R13 RED: replay/conflict/expiry decisions and the stored response are made
// under the same transaction as node insertion.
func TestR13NodeBundleReplayConflictAndExpiry(t *testing.T) {
	s := openTestStore(t)
	bundler := requireR13NodeBundler(t, s)
	previousNow := now
	clock := int64(10_000)
	now = func() int64 { return clock }
	t.Cleanup(func() { now = previousNow })

	firstRec := r13NodeRecord("r13-node-key", "hash-a")
	firstRec.ExpiresAt = clock + 10
	first, replayed, err := bundler.CreateNodeBundle(context.Background(), Node{ID: "node-first", Name: "node-first"}, firstRec)
	if err != nil || replayed || first.ResponseBody == "" {
		t.Fatalf("first bundle = replayed %v record %+v err %v", replayed, first, err)
	}
	second, replayed, err := bundler.CreateNodeBundle(context.Background(), Node{ID: "node-duplicate", Name: "node-duplicate"}, firstRec)
	if err != nil || !replayed || second.ResponseBody != first.ResponseBody {
		t.Fatalf("matching replay = replayed %v record %+v err %v, want exact first response", replayed, second, err)
	}
	if _, err := s.GetNode("node-duplicate"); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("matching replay created a second node: %v", err)
	}
	conflictRec := firstRec
	conflictRec.RequestHash = "hash-b"
	if _, _, err := bundler.CreateNodeBundle(context.Background(), Node{ID: "node-conflict", Name: "node-conflict"}, conflictRec); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different-hash reuse = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := s.GetNode("node-conflict"); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("conflicting reuse created a node: %v", err)
	}

	clock += 11
	expiredRec := r13NodeRecord("r13-node-key", "hash-c")
	third, replayed, err := bundler.CreateNodeBundle(context.Background(), Node{ID: "node-after-expiry", Name: "node-after-expiry"}, expiredRec)
	if err != nil || replayed || third.ResponseBody == first.ResponseBody {
		t.Fatalf("expired reuse = replayed %v record %+v err %v", replayed, third, err)
	}
	if events, err := countRows(t, s, `SELECT COUNT(*) FROM admin_events WHERE event_type = 'IDEMPOTENCY_KEY_EXPIRED'`); err != nil || events != 1 {
		t.Fatalf("expiry audit count = %d (err=%v), want 1", events, err)
	}
}

// R13 RED: BEGIN IMMEDIATE serializes same-key creators so every contender
// returns the same stored response and only the winner inserts a node.
func TestR13NodeBundleConcurrentSameKeyReplaysWinner(t *testing.T) {
	s := openTestStore(t)
	bundler := requireR13NodeBundler(t, s)
	const workers = 8
	start := make(chan struct{})
	type result struct {
		rec      IdempotencyRecord
		replayed bool
		err      error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec, replayed, err := bundler.CreateNodeBundle(context.Background(), Node{
				ID: fmt.Sprintf("node-%d", i), Name: fmt.Sprintf("node-%d", i),
			}, r13NodeRecord("r13-concurrent-key", "same-hash"))
			results <- result{rec: rec, replayed: replayed, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var body string
	created := 0
	for got := range results {
		if got.err != nil {
			t.Fatalf("concurrent bundle: %v", got.err)
		}
		if !got.replayed {
			created++
		}
		if body == "" {
			body = got.rec.ResponseBody
		} else if got.rec.ResponseBody != body {
			t.Fatalf("concurrent stored responses differ: %q != %q", got.rec.ResponseBody, body)
		}
	}
	if created != 1 {
		t.Fatalf("new bundle winners = %d, want 1", created)
	}
	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes after concurrent bundle = %d (err=%v), want 1", len(nodes), err)
	}
}

// R13 RED: even an absent runtime mirror may only be inserted for the
// forward's current activation. The pre-repair UPSERT applied the CAS only to
// its conflict arm, so the first stale status inserted successfully.
func TestR13RuntimeStatusInsertCASUsesCurrentActivation(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateNode(Node{ID: "node-runtime-r13", Name: "node-runtime-r13"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "forward-runtime-r13", NodeID: "node-runtime-r13", Name: "runtime", Protocol: "tcp", CurrentActivationID: "activation-new", Revision: 2}); err != nil {
		t.Fatal(err)
	}
	snapshot := `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"NOT_REQUIRED","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"UNKNOWN","publication_state":"NONE","data_plane_state":"READY"}`
	if err := s.SetForwardRuntimeStatus("forward-runtime-r13", "activation-old", 2, snapshot); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale absent-mirror insert = %v, want ErrCASConflict", err)
	}
	if _, err := s.GetForwardRuntimeStatus("forward-runtime-r13"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale insert created runtime mirror: %v", err)
	}
}

// R13 recovery RED: a mirror that still names the previous activation must
// not make another previous-activation update legal after the forward advances.
// The write predicate itself, not a preceding read, owns this fence.
func TestR13RuntimeStatusExistingRowCASUsesCurrentActivation(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateNode(Node{ID: "node-runtime-existing-r13", Name: "node-runtime-existing-r13"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "forward-runtime-existing-r13", NodeID: "node-runtime-existing-r13", Name: "runtime-existing",
		Protocol: "tcp", CurrentActivationID: "activation-old", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	oldSnapshot := `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"NOT_REQUIRED","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"UNKNOWN","publication_state":"NONE","data_plane_state":"READY"}`
	if err := s.SetForwardRuntimeStatus("forward-runtime-existing-r13", "activation-old", 1, oldSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := s.CASForwardActivation("forward-runtime-existing-r13", 1, "activation-new"); err != nil {
		t.Fatal(err)
	}
	staleSnapshot := `{"control_state":"OFFLINE","listener_state":"ERROR","mapping_state":"ERROR","keepalive_state":"LOST","wan_reachability_state":"REJECTED","return_path_state":"FAILED","target_health_state":"FAIL","publication_state":"UNPUBLISHED","data_plane_state":"DEGRADED"}`
	if err := s.SetForwardRuntimeStatus("forward-runtime-existing-r13", "activation-old", 2, staleSnapshot); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("same-old-activation update after forward advance = %v, want ErrCASConflict", err)
	}
	got, err := s.GetForwardRuntimeStatus("forward-runtime-existing-r13")
	if err != nil {
		t.Fatal(err)
	}
	if got.ActivationID != "activation-old" || got.SnapshotJSON != oldSnapshot {
		t.Fatalf("stale update mutated mirror: %+v", got)
	}
}

func createR13TerminalProbe(t *testing.T, s *Store, id, forwardID, activationID string, updatedAt int64) {
	t.Helper()
	createR13TerminalProbeForNode(t, s, id, "node-delivery-r13", forwardID, activationID, updatedAt)
}

func createR13TerminalProbeForNode(t *testing.T, s *Store, id, nodeID, forwardID, activationID string, updatedAt int64) {
	t.Helper()
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: id, NodeID: nodeID, ForwardID: forwardID, ActivationID: activationID,
		ProviderID: "provider-r13", Status: string(protocol.OutcomeRejected), Endpoint: "198.51.100.7:8080",
		ExpiresAt: updatedAt + 100,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE probe_operations SET created_at = ?, updated_at = ? WHERE id = ?`, updatedAt, updatedAt, id); err != nil {
		t.Fatal(err)
	}
}

// R13 RED: stale/missing activations receive durable terminal dispositions;
// only the current activation gets an outbox command.
func TestR13TerminalProbeDispositionIsDurable(t *testing.T) {
	s := openTestStore(t)
	delivery := requireR13ProbeDeliveryStore(t, s)
	if err := s.CreateNode(Node{ID: "node-delivery-r13", Name: "node-delivery-r13"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "forward-delivery-r13", NodeID: "node-delivery-r13", Name: "delivery", Protocol: "tcp", CurrentActivationID: "activation-current", Revision: 3}); err != nil {
		t.Fatal(err)
	}
	createR13TerminalProbe(t, s, "probe-stale", "forward-delivery-r13", "activation-old", 10)
	createR13TerminalProbe(t, s, "probe-missing", "forward-missing-r13", "activation-old", 11)
	createR13TerminalProbe(t, s, "probe-current", "forward-delivery-r13", "activation-current", 12)

	for id, want := range map[string]string{"probe-stale": "STALE", "probe-missing": "MISSING", "probe-current": "ENQUEUED"} {
		got, err := delivery.QueueProbeOutcome(id, protocol.OutcomeRejected)
		if err != nil || got != want {
			t.Fatalf("queue %s = %q, %v; want %q", id, got, err, want)
		}
	}
	for id, want := range map[string]string{"probe-stale": "STALE", "probe-missing": "MISSING"} {
		got, err := delivery.ProbeOutcomeDisposition(id)
		if err != nil || got != want {
			t.Fatalf("disposition %s = %q, %v; want %q", id, got, err, want)
		}
		if _, err := s.ControlOutboxItemByOperation(id, "probe_outcome"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("disposed probe %s retained outbox: %v", id, err)
		}
	}
	if _, err := s.ControlOutboxItemByOperation("probe-current", "probe_outcome"); err != nil {
		t.Fatalf("current activation outcome was not queued: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE probe_operations SET updated_at = 1 WHERE id IN ('probe-stale', 'probe-missing')`); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.DeleteTerminalProbeOperationsBeforeLimit(2, 10); err != nil || removed != 2 {
		t.Fatalf("stale/missing terminal retention cleanup = %d, %v; want 2", removed, err)
	}
	for _, id := range []string{"probe-stale", "probe-missing"} {
		if _, err := delivery.ProbeOutcomeDisposition(id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("disposed terminal %s survived retention cleanup: %v", id, err)
		}
	}
}

// R13 RED: terminal recovery selects only eligible rows in an indexed,
// deterministic, caller-budgeted page instead of rescanning all history.
func TestR13TerminalProbeSelectionIsIndexedAndBounded(t *testing.T) {
	s := openTestStore(t)
	delivery := requireR13ProbeDeliveryStore(t, s)
	if err := s.CreateNode(Node{ID: "node-delivery-r13", Name: "node-delivery-r13"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "forward-delivery-r13", NodeID: "node-delivery-r13", Name: "delivery", Protocol: "tcp", CurrentActivationID: "activation-current", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		createR13TerminalProbe(t, s, fmt.Sprintf("probe-page-%d", i), "forward-delivery-r13", "activation-current", int64(20+i))
	}
	page, err := delivery.ListUndeliveredTerminalProbeOperationsPage(2, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].ID != "probe-page-0" || page[1].ID != "probe-page-1" {
		t.Fatalf("first bounded delivery page = %+v", page)
	}
	var schemaSQL string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_probe_terminal_delivery'`).Scan(&schemaSQL); err != nil ||
		!strings.Contains(schemaSQL, "probe_operations") || !strings.Contains(schemaSQL, "created_at") {
		t.Fatalf("terminal delivery index missing: sql=%q err=%v", schemaSQL, err)
	}
}

func TestR13TerminalSelectionRepairsLegacyIndexDefinition(t *testing.T) {
	s := openR14LegacyV5(t, filepath.Join(t.TempDir(), "controller.db"))
	defer s.Close()
	if _, err := s.db.Exec(`CREATE INDEX idx_probe_terminal_delivery ON probe_operations(status, updated_at, id)`); err != nil {
		t.Fatal(err)
	}
	sqlBytes, err := migrations.FS.ReadFile("0006_r13_hardening.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyMigration(6, "0006_r13_hardening.sql", string(sqlBytes)); err != nil {
		t.Fatal(err)
	}
	var schemaSQL string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_probe_terminal_delivery'`).Scan(&schemaSQL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(schemaSQL, "created_at") {
		t.Fatalf("legacy terminal delivery index was not repaired: %q", schemaSQL)
	}
}

// R13 RED: an offline node cannot retain a terminal outbox/tombstone forever.
// Once retention elapses, the delivery gets an EXPIRED disposition and the
// old tombstone becomes eligible for bounded cleanup.
func TestR13TerminalProbeOfflineDeliveryHasFiniteRetention(t *testing.T) {
	s := openTestStore(t)
	delivery := requireR13ProbeDeliveryStore(t, s)
	if err := s.CreateNode(Node{ID: "node-delivery-r13", Name: "node-delivery-r13"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "forward-delivery-r13", NodeID: "node-delivery-r13", Name: "delivery", Protocol: "tcp", CurrentActivationID: "activation-current", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	createR13TerminalProbe(t, s, "probe-offline", "forward-delivery-r13", "activation-current", 1)
	if got, err := delivery.QueueProbeOutcome("probe-offline", protocol.OutcomeRejected); err != nil || got != "ENQUEUED" {
		t.Fatalf("initial queue = %q, %v", got, err)
	}
	expired, err := delivery.ExpireTerminalProbeDeliveriesBeforeLimit(100, 1)
	if err != nil || expired != 1 {
		t.Fatalf("expired deliveries = %d, %v; want 1", expired, err)
	}
	if got, err := delivery.ProbeOutcomeDisposition("probe-offline"); err != nil || got != "EXPIRED" {
		t.Fatalf("offline disposition = %q, %v; want EXPIRED", got, err)
	}
	if _, err := s.ControlOutboxItemByOperation("probe-offline", "probe_outcome"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired offline outbox still exists: %v", err)
	}
	removed, err := s.DeleteTerminalProbeOperationsBeforeLimit(100, 1)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup after expired delivery = %d, %v; want 1", removed, err)
	}
}
