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

func testPumpSession(t *testing.T, h *Hub, serverConn *websocket.Conn, owner store.ControlOwner) *ControlSession {
	t.Helper()
	return &ControlSession{
		hub:     h,
		nodeID:  owner.NodeID,
		epoch:   owner.ConnectionEpoch,
		session: owner.SessionID,
		owner:   owner,
		conn:    serverConn,
		closed:  make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func TestOutboxPumpRequeueFailureClosesSession(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/control", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseNow()
	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-ctx.Done():
		t.Fatalf("server did not accept WebSocket: %v", ctx.Err())
	}

	owner := store.ControlOwner{NodeID: "node-pump", ConnectionEpoch: 1, SessionID: "session-pump"}
	s := testPumpSession(t, h, serverConn, owner)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	pumpDone := make(chan struct{})
	go func() {
		h.outboxPump(context.Background(), s)
		close(pumpDone)
	}()
	select {
	case <-s.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("outbox pump left session open after requeue failure")
	}
	select {
	case <-pumpDone:
	case <-time.After(2 * time.Second):
		t.Fatal("outbox pump did not terminate after requeue failure")
	}
}
