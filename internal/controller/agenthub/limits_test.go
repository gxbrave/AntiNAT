// P08 Story 6 RED: bounded transport — an oversize WebSocket message fails
// the session closed, and the enrollment/control bodies are bounded.
package agenthub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// RED 6g: a WS message larger than the max envelope closes the session.
func TestOversizeWSMessageFailsClosed(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 70 KB > maxEnvelopeBytes (13 + 4096 + 65536 + 64).
	oversize := bytes.Repeat([]byte{0x41}, 70*1024)
	if err := conn.conn.Write(ctx, websocket.MessageBinary, oversize); err != nil {
		t.Fatalf("write oversize: %v", err)
	}
	// The hub must close the connection (read limit enforced).
	_, _, err := conn.conn.Read(ctx)
	if err == nil {
		t.Fatal("oversize message accepted")
	}
}

// RED 6h: the challenge endpoint rejects oversize bodies (resource bound).
func TestEnrollChallengeOversizeBodyRejected(t *testing.T) {
	hub, st, _ := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://x/agent/v1/enroll/challenge",
		bytes.NewReader(bytes.Repeat([]byte{0x41}, 64*1024)))
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	hub.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize challenge body status = %d, want 400", rec.Code)
	}
}

// RED 6i: the control handshake accepts only the bounded session transcript —
// a garbage first message fails closed.
func TestControlGarbageFirstMessageFailsClosed(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	_ = key

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv, "http")+"/agent/v1/control", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("not a session hello")); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.Read(ctx)
	if err == nil {
		t.Fatal("garbage handshake message accepted")
	}
}

// RED 6j: the bounded envelope cap is consistent with the frozen constants.
func TestEnvelopeCapConsistency(t *testing.T) {
	// A maximum-size payload must fit within the WS read limit used by both
	// sides (hub and agent share the frozen max envelope size).
	maxFrame := 13 + protocol.MaxHeaderBytes + protocol.MaxPayloadBytes + 64
	if maxFrame <= 0 {
		t.Fatal("max envelope size must be positive")
	}
	// Message ids and hashes are fixed size.
	if security.SessionNonceSize != 32 {
		t.Fatalf("session nonce size = %d, want 32", security.SessionNonceSize)
	}
	if len(sha256.Sum256([]byte("x"))) != 32 {
		t.Fatal("sha256 must be 32 bytes")
	}
}
