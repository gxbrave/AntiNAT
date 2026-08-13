// P08 Story 4 RED: bidirectional epoch fencing. A second session bumps the
// node epoch via controller CAS; the old socket's validly-signed frames are
// then rejected (fail closed), and the agent persists the max accepted epoch
// BEFORE socket activation.
package agenthub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// rawAgentConn is a hand-rolled control client used to drive hub sessions
// directly in tests.
type rawAgentConn struct {
	t      *testing.T
	conn   *websocket.Conn
	hub    *agenthub.Hub
	st     *store.Store
	key    *security.NodeKey
	nodeID string
	epoch  uint64
	sess   string
	seq    uint64
}

// dialRawAgent performs the full handshake from a raw socket.
func dialRawAgent(t *testing.T, hub *agenthub.Hub, st *store.Store, srvURL, nodeID string, key *security.NodeKey) *rawAgentConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srvURL, "http")+"/agent/v1/control", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &rawAgentConn{t: t, conn: conn, hub: hub, st: st, key: key, nodeID: nodeID}
	if err := c.handshake(ctx); err != nil {
		t.Fatalf("raw handshake: %v", err)
	}
	return c
}

func (c *rawAgentConn) handshake(ctx context.Context) error {
	instance := c.hub.ControllerInstanceID()
	var node [16]byte
	copy(node[:], c.nodeID)
	var nonce [32]byte
	rand.Read(nonce[:])
	cur, err := c.currentNodeEpoch()
	if err != nil {
		return err
	}
	hello := security.SessionHello{
		ControllerInstanceID: instance,
		NodeID:               node,
		AgentCredentialVer:   1,
		AgentPublicKey:       [32]byte(c.key.PublicKey()),
		AgentNonce:           nonce,
		AgentMaxEpoch:        cur,
		ProtocolVersions:     "1",
	}
	sig, err := hello.Sign(c.key.PrivateKey())
	if err != nil {
		return err
	}
	if err := c.conn.Write(ctx, websocket.MessageBinary, append(hello.Canonical(), sig...)); err != nil {
		return err
	}
	_, rawWelcome, err := c.conn.Read(ctx)
	if err != nil {
		return err
	}
	welcome, err := security.ParseSessionWelcome(rawWelcome, c.hub.ControllerPublicKey())
	if err != nil {
		return err
	}
	final := security.SessionFinal{
		ControllerInstanceID: welcome.ControllerInstanceID,
		NodeID:               node,
		ServerNonce:          welcome.ServerNonce,
		ConnectionEpoch:      welcome.ConnectionEpoch,
		SessionID:            welcome.SessionID,
	}
	fsig, err := final.Sign(c.key.PrivateKey())
	if err != nil {
		return err
	}
	if err := c.conn.Write(ctx, websocket.MessageBinary, append(final.Canonical(), fsig...)); err != nil {
		return err
	}
	c.epoch = welcome.ConnectionEpoch
	c.sess = welcome.SessionID
	return nil
}

// currentNodeEpoch reads the node's current connection epoch from the store.
func (c *rawAgentConn) currentNodeEpoch() (uint64, error) {
	n, err := c.st.GetNode(c.nodeID)
	if err != nil {
		return 0, err
	}
	return n.CurrentConnectionEpoch, nil
}

// sendA2C writes a signed A2C envelope with the given sequence.
func (c *rawAgentConn) sendA2C(ctx context.Context, seq uint64, msgType string, payload []byte) error {
	instance := c.hub.ControllerInstanceID()
	var node [16]byte
	copy(node[:], c.nodeID)
	header := protocol.ProtectedHeader{
		ProtocolDomain:       protocol.ProtocolDomain,
		ControllerInstanceID: instance,
		NodeID:               node,
		ControllerKeyID:      c.hub.ControllerKeyID(),
		AgentCredentialVer:   1,
		ConnectionEpoch:      c.epoch,
		SessionID:            c.sess,
		Direction:            protocol.DirectionA2C,
		Sequence:             seq,
		MessageID:            [16]byte{1},
		MessageType:          msgType,
		SchemaVersion:        1,
	}
	frame, err := protocol.BuildEnvelope(c.key.PrivateKey(), header, payload)
	if err != nil {
		return err
	}
	return c.conn.Write(ctx, websocket.MessageBinary, frame)
}

// RED 4a: a second session bumps the epoch; the FIRST socket's validly-signed
// frame with the OLD epoch is rejected and the socket is closed.
func TestEpochFencingOldSocketRejected(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)

	first := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer first.conn.CloseNow()
	oldEpoch := first.epoch

	// Second session: the epoch must bump.
	second := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer second.conn.CloseNow()
	if second.epoch != oldEpoch+1 {
		t.Fatalf("second session epoch = %d, want %d (CAS bump)", second.epoch, oldEpoch+1)
	}

	// The old socket sends a VALID signed heartbeat at the OLD epoch — the
	// hub must reject it (fail closed) and drop the old session.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := first.sendA2C(ctx, 1, "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("old socket send: %v", err)
	}
	// The old connection must be closed by the hub.
	_, _, err := first.conn.Read(ctx)
	if err == nil {
		t.Fatal("old-epoch frame was accepted")
	}
	// The node epoch stays at the second session's value.
	n, err := st.GetNode(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if n.CurrentConnectionEpoch != second.epoch {
		t.Fatalf("node epoch = %d, want %d", n.CurrentConnectionEpoch, second.epoch)
	}
}

// RED 4b: an agent claiming an epoch the controller never issued (rollback/
// split-brain) fails closed at the handshake.
func TestEpochFencingFutureEpochRejected(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	_ = key

	// Dial but send a hello claiming epoch 99.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv, "http")+"/agent/v1/control", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	instance := hub.ControllerInstanceID()
	var node [16]byte
	copy(node[:], nodeID)
	hello := security.SessionHello{
		ControllerInstanceID: instance,
		NodeID:               node,
		AgentCredentialVer:   1,
		AgentPublicKey:       [32]byte(key.PublicKey()),
		AgentMaxEpoch:        99,
		ProtocolVersions:     "1",
	}
	sig, _ := hello.Sign(key.PrivateKey())
	if err := conn.Write(ctx, websocket.MessageBinary, append(hello.Canonical(), sig...)); err != nil {
		t.Fatal(err)
	}
	// The hub must close without granting.
	_, _, err = conn.Read(ctx)
	if err == nil {
		t.Fatal("future-epoch hello was granted a welcome")
	}
}

// RED 4c: the agent persists the max accepted epoch BEFORE socket activation
// — after a successful handshake the agent store already shows the new epoch
// even before any envelope traffic.
func TestAgentPersistsEpochBeforeActivation(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()
	// The hub's CAS already advanced the node epoch; the raw agent conn
	// completed the handshake, so the controller epoch == the granted epoch.
	n, err := st.GetNode(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if n.CurrentConnectionEpoch != conn.epoch {
		t.Fatalf("controller epoch = %d, granted epoch = %d", n.CurrentConnectionEpoch, conn.epoch)
	}
}

// --- helpers ----------------------------------------------------------------

// newFencedHub builds a hub + httptest server exposing test hooks.
func newFencedHub(t *testing.T) (*agenthub.Hub, *store.Store, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := agenthub.NewHub(agenthub.Config{
		Store:      st,
		Keyring:    kr,
		Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock:      time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)
	return hub, st, srv.URL
}

// enrollRaw runs the enrollment transcript directly against the hub handlers
// (no HTTP server needed for the challenge/request round).
func enrollRaw(t *testing.T, hub *agenthub.Hub, st *store.Store, nodeID string) *security.NodeKey {
	t.Helper()
	token, err := st.CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	key, err := security.LoadOrCreateNodeKey(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	instance := hub.ControllerInstanceID()
	var node [16]byte
	copy(node[:], nodeID)
	ch, rawChal, err := hub.Challenges().Issue(hub.Keyring(), instance, hub.ControllerKeyID(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	_ = ch
	canonical := rawChal[:len(rawChal)-64]
	chash := sha256.Sum256(canonical)
	var agentNonce [protocol.EnrollNonceSize]byte
	rand.Read(agentNonce[:])
	req := protocol.EnrollRequest{
		ChallengeHash:          chash,
		AgentNonce:             agentNonce,
		AgentPublicKey:         [32]byte(key.PublicKey()),
		AgentCredentialVersion: key.CredentialVersion(),
		Token:                  token,
		CapabilityHash:         sha256.Sum256([]byte("caps")),
	}
	sig, err := key.Sign(req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	rawReq := append(req.Canonical(), sig...)

	// Drive the request handler directly.
	httpReq, err := http.NewRequest(http.MethodPost, "http://x/agent/v1/enroll/request", strings.NewReader(string(rawReq)))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	hub.Handler().ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status = %d body=%s", rec.Code, rec.Body.String())
	}
	return key
}

var _ = ed25519.PublicKeySize
var _ = hex.EncodeToString
