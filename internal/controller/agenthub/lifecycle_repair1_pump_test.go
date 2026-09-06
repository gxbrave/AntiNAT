// P14 repair-1 H2c/M3a/L4 agenthub tests: the outbox pump re-gates delivery AT
// DELIVERY TIME per tick. A cleanup tombstone or a RESTORE_RECONCILIATION
// created AFTER a session was established (so the handshake-captured cleanupOnly
// is still false) must still block forbidden orchestrating rows that were
// enqueued before the tombstone/quarantine, and the denied row is requeued
// (kept owned, retryable) rather than stranded in CLAIMED forever.
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
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func pumpProbeSession(t *testing.T, h *Hub, serverConn *websocket.Conn, owner store.ControlOwner) {
	t.Helper()
	s := testPumpSession(t, h, serverConn, owner)

	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()
	delivered := make(chan string, 64)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			_, frame, err := serverConn.Read(readCtx)
			if err != nil {
				return
			}
			env, _, perr := protocol.ParseEnvelope(frame, h.Keyring().PublicKey())
			if perr != nil {
				continue
			}
			delivered <- env.Header.MessageType
		}
	}()

	pumpCtx, pumpCancel := context.WithCancel(context.Background())
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		h.outboxPump(pumpCtx, s)
	}()
	time.Sleep(600 * time.Millisecond)
	pumpCancel()
	<-pumpDone
	readCancel()
	<-readerDone

	close(delivered)
	for mt := range delivered {
		if mt == "desired" || mt == "probe_arm" {
			t.Fatalf("forbidden orchestrating row %q delivered by a pre-tombstone/quarantine session", mt)
		}
	}
}

func TestOutboxPumpSkipsPreEnqueuedRowsAfterTombstoneAndRequeues(t *testing.T) {
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

	if err := st.CreateNode(store.Node{ID: "node-m3", Name: "n3"}); err != nil {
		t.Fatal(err)
	}
	owner, err := st.AcquireControlOwner("node-m3", 0, "session-m3")
	if err != nil {
		t.Fatal(err)
	}
	// The row is enqueued BEFORE the tombstone exists (pre-tombstone issuance).
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "m3-desired", MessageType: "desired", NodeID: "node-m3",
		SemanticPayload: `{"node_id":"node-m3","forwards":[]}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Set up the established session BEFORE the tombstone so cleanupOnly=false.
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

	// NOW the tombstone appears: this session (cleanupOnly=false) must stop
	// pumping the pre-tombstone desired row.
	if err := st.CreateNodeCleanupTombstone(store.NodeCleanupTombstone{
		NodeID: "node-m3", OperationID: "tomb-m3", Force: true,
	}); err != nil {
		t.Fatal(err)
	}

	pumpProbeSession(t, h, serverConn, owner)

	// The denied row must be retryable (PENDING or CLAIMED — never SENT, never
	// SEMANTIC_ACKED, never GC'd).
	item, err := st.ControlOutboxItemByOperation("m3-desired", "desired")
	if err != nil {
		t.Fatalf("denied row was leaked: %v", err)
	}
	if item.State == "SENT" || item.State == "SEMANTIC_ACKED" {
		t.Fatalf("denied row reached %q after tombstone", item.State)
	}
}

func TestOutboxPumpSkipsPreEnqueuedRowsDuringRestoreReconciliation(t *testing.T) {
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

	if err := st.CreateNode(store.Node{ID: "node-m3q", Name: "n3q"}); err != nil {
		t.Fatal(err)
	}
	owner, err := st.AcquireControlOwner("node-m3q", 0, "session-m3q")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "m3q-probe", MessageType: "probe_arm", NodeID: "node-m3q",
		SemanticPayload: `{}`,
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

	// A restore enters RESTORE_RECONCILIATION: no forbidden orchestrating row
	// may flow even though it was enqueued and the session predates the restore.
	if err := st.EnterRestoreReconciliation(store.RestoreOperation{
		ID: "rest-m3q", ControllerInstance: "ci-1", ManifestSHA256: "abc", SchemaVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}

	pumpProbeSession(t, h, serverConn, owner)

	item, err := st.ControlOutboxItemByOperation("m3q-probe", "probe_arm")
	if err != nil {
		t.Fatalf("denied row was leaked: %v", err)
	}
	if item.State == "SENT" || item.State == "SEMANTIC_ACKED" {
		t.Fatalf("denied row reached %q during RESTORE_RECONCILIATION", item.State)
	}
}
