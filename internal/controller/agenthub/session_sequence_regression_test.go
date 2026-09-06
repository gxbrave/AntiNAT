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

func TestWriteEnvelopeBuildFailureDoesNotConsumeSequence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHub(Config{
		Store:      st,
		Keyring:    kr,
		Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock:      time.Now,
	})
	if err != nil {
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

	s := &ControlSession{
		hub:     h,
		nodeID:  "node-sequence",
		epoch:   1,
		session: "session-sequence",
		conn:    serverConn,
		closed:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	oversized := make([]byte, protocol.MaxPayloadBytes+1)
	if err := s.writeEnvelope(ctx, [16]byte{1}, "desired", oversized); err == nil {
		t.Fatal("oversized envelope unexpectedly succeeded")
	}
	s.mu.Lock()
	gotSeq := s.outSeq
	s.mu.Unlock()
	if gotSeq != 0 {
		t.Fatalf("outbound sequence after local build failure = %d, want 0", gotSeq)
	}

	if err := s.writeEnvelope(ctx, [16]byte{2}, "desired", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("valid envelope after local build failure: %v", err)
	}
	_, raw, err := clientConn.Read(ctx)
	if err != nil {
		t.Fatalf("read valid envelope: %v", err)
	}
	env, stage, err := protocol.ParseEnvelope(raw, kr.PublicKey())
	if err != nil {
		t.Fatalf("parse valid envelope at %s: %v", stage, err)
	}
	if env.Header.Sequence != 1 {
		t.Fatalf("valid envelope sequence = %d, want 1", env.Header.Sequence)
	}
}
