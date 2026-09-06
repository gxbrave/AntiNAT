// P14 repair-2 L-B outbox pump no-spin test: a delivery-refused outbox row
// (cleanup-only node, RESTORE_RECONCILIATION, per-node quarantine) must NOT be
// re-claimed on every pump tick. Before the fix the pump claimed the row,
// DeliveryAllowed refused it, and RequeueControlOutboxItemOwned reset it to
// PENDING — a permanent PENDING→CLAIMED cycle. Now the requeue schedules a
// bounded retry_after_unix backoff so the row quiesces until reauthorization.
package agenthub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func TestOutboxPumpDoesNotHotSpinRefusedProbeOutcomeRow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	h, err := NewHub(Config{
		Store:      st,
		Keyring:    kr,
		Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock:      time.Now,
	})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateNode(store.Node{ID: "node-r2p", Name: "r2p"}); err != nil {
		t.Fatal(err)
	}
	owner, err := st.AcquireControlOwner("node-r2p", 0, "session-r2p")
	if err != nil {
		t.Fatal(err)
	}
	// The probe_outcome row is enqueued BEFORE the tombstone so its issuance is
	// legal; the tombstone appears after, exactly the pre-existing-row scenario
	// the delivery-time gate must handle without spinning.
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "r2p-probe", MessageType: "probe_outcome", NodeID: "node-r2p",
		SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-r2p", OperationID: "tomb-r2p", Force: true,
	}); err != nil {
		t.Fatal(err)
	}

	serverConnCh := make(chan *websocket.Conn, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		serverConnCh <- conn
		<-release
		conn.CloseNow()
	}))
	defer srv.Close()
	defer close(release)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	clientConn, _, err := websocket.Dial(dialCtx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/control", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseNow()
	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-dialCtx.Done():
		t.Fatalf("server did not accept WebSocket: %v", dialCtx.Err())
	}

	// A reader goroutine ignores the frames; the assertion is that the forbidden
	// row is never delivered, not what the (empty) frames are.
	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			if _, _, err := serverConn.Read(readCtx); err != nil {
				return
			}
		}
	}()

	s := testPumpSession(t, h, serverConn, owner)
	pumpCtx, pumpCancel := context.WithCancel(context.Background())
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		h.outboxPump(pumpCtx, s)
	}()
	// Several pump ticks (outboxPumpInterval = 100ms) that a hot spin would
	// churn through.
	time.Sleep(450 * time.Millisecond)
	pumpCancel()
	<-pumpDone
	readCancel()
	<-readerDone

	item, err := st.ControlOutboxItemByOperation("r2p-probe", "probe_outcome")
	if err != nil {
		t.Fatalf("refused row was leaked: %v", err)
	}
	if item.State == "SENT" || item.State == "SEMANTIC_ACKED" {
		t.Fatalf("probe_outcome delivered to a cleanup-only node (%s)", item.State)
	}
	if item.RetryAfterUnix <= time.Now().Unix() {
		t.Fatalf("refused row retry_after_unix = %d is not in the future; the pump re-claims it on every tick (hot spin)", item.RetryAfterUnix)
	}
	// After the backoff window the row must still be PENDING (quiesced), not
	// oscillating through CLAIMED on each tick.
	if _, err := st.ClaimControlOutboxOwned(owner, 10); err != nil {
		t.Fatal(err)
	}
	item, err = st.ControlOutboxItemByOperation("r2p-probe", "probe_outcome")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != "PENDING" {
		t.Fatalf("refused row was re-claimed after the denial backoff: state = %q", item.State)
	}
}
