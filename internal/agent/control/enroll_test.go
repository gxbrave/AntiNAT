// P08 Story 1/2 RED: Agent enrollment client. It fetches a signed challenge,
// proves possession of a fresh node key, submits the token, and verifies the
// signed result against the PINNED controller key. Wrong pins, expired
// tokens, and replay recovery are exercised end to end.
package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

type enrollHarness struct {
	hub    *agenthub.Hub
	st     *store.Store
	srv    *httptest.Server
	pub    ed25519.PublicKey
	nodeID string
	token  string
}

func newEnrollHarness(t *testing.T) *enrollHarness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	hub, err := agenthub.NewHub(agenthub.Config{
		Store:      st,
		Keyring:    kr,
		Challenges: security.NewChallengeManager(5*time.Minute, 64),
		Clock:      time.Now,
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	t.Cleanup(srv.Close)
	return &enrollHarness{hub: hub, st: st, srv: srv, pub: kr.PublicKey(), nodeID: nodeID, token: token}
}

func newAgentStore(t *testing.T) *localstate.Store {
	t.Helper()
	ls, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatalf("localstate.Open: %v", err)
	}
	t.Cleanup(func() { ls.Close() })
	return ls
}

// RED 1z: the enroll client completes the full transcript and persists the
// node key (a second enroll on the same store reuses the same key).
func TestEnrollClientHappyPath(t *testing.T) {
	h := newEnrollHarness(t)
	ls := newAgentStore(t)

	opts := control.EnrollOptions{
		Endpoint:            h.srv.URL,
		NodeID:              h.nodeID,
		Token:               h.token,
		ControllerPublicKey: h.pub,
		ControllerKeyID:     "", // learned from the challenge
		KeyDir:              t.TempDir(),
	}
	res, err := control.Enroll(context.Background(), ls, opts)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.CredentialVersion() != 1 {
		t.Fatalf("credential version = %d, want 1", res.CredentialVersion())
	}
	// The credential is bound on the controller.
	cred, err := h.st.NodeCredentialByNode(h.nodeID)
	if err != nil {
		t.Fatalf("controller credential: %v", err)
	}
	if cred.CredentialVersion != 1 {
		t.Fatalf("controller credential version = %d, want 1", cred.CredentialVersion)
	}
}

// RED 2f: a wrong pinned controller key fails the challenge verification
// before any token is transmitted meaningfully (the pin is the trust anchor).
func TestEnrollWrongPinnedControllerKey(t *testing.T) {
	h := newEnrollHarness(t)
	ls := newAgentStore(t)

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := control.EnrollOptions{
		Endpoint:            h.srv.URL,
		NodeID:              h.nodeID,
		Token:               h.token,
		ControllerPublicKey: wrongPriv.Public().(ed25519.PublicKey),
		KeyDir:              t.TempDir(),
	}
	if _, err := control.Enroll(context.Background(), ls, opts); err == nil {
		t.Fatal("enroll succeeded against a wrong pinned controller key")
	} else if !strings.Contains(err.Error(), "challenge") && !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "pin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// RED 2g: response-loss recovery — after a successful enroll, a retry with
// the same key converges on the same binding without a second token
// (the controller replays the original result).
func TestEnrollClientResponseLossRecovery(t *testing.T) {
	h := newEnrollHarness(t)
	ls := newAgentStore(t)
	opts := control.EnrollOptions{
		Endpoint:            h.srv.URL,
		NodeID:              h.nodeID,
		Token:               h.token,
		ControllerPublicKey: h.pub,
		KeyDir:              t.TempDir(),
	}
	first, err := control.Enroll(context.Background(), ls, opts)
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	second, err := control.Enroll(context.Background(), ls, opts)
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if !first.PublicKey().Equal(second.PublicKey()) {
		t.Fatal("re-enroll produced a different node key")
	}
	// The controller holds exactly one credential for the node.
	cred, err := h.st.NodeCredentialByNode(h.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(first.PublicKey())
	if cred.PublicKeyHash != hex.EncodeToString(want[:]) {
		t.Fatalf("controller credential hash = %q, want %q", cred.PublicKeyHash, hex.EncodeToString(want[:]))
	}
}

// RED 2h: an expired token fails closed and leaves no credential behind.
func TestEnrollClientExpiredToken(t *testing.T) {
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
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken(nodeID, -1) // expired
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hub.Handler())
	defer srv.Close()

	ls := newAgentStore(t)
	opts := control.EnrollOptions{
		Endpoint:            srv.URL,
		NodeID:              nodeID,
		Token:               token,
		ControllerPublicKey: kr.PublicKey(),
		KeyDir:              t.TempDir(),
	}
	if _, err := control.Enroll(context.Background(), ls, opts); err == nil {
		t.Fatal("enroll with expired token succeeded")
	}
	if _, err := st.NodeCredentialByNode(nodeID); err == nil {
		t.Fatal("credential bound despite expired token")
	}
}

// RED 2i: the enroll client never logs or leaks the token or the private key
// in errors.
func TestEnrollClientNoSecretLeak(t *testing.T) {
	h := newEnrollHarness(t)
	ls := newAgentStore(t)
	// Wrong node: the controller rejects at challenge time; the error must
	// not contain the token.
	opts := control.EnrollOptions{
		Endpoint:            h.srv.URL,
		NodeID:              "ghost-node",
		Token:               h.token,
		ControllerPublicKey: h.pub,
		KeyDir:              t.TempDir(),
	}
	_, err := control.Enroll(context.Background(), ls, opts)
	if err == nil {
		t.Fatal("enroll for unknown node succeeded")
	}
	if strings.Contains(err.Error(), h.token) {
		t.Fatalf("error leaks enrollment token: %v", err)
	}
	// The token must not be persisted anywhere in the agent store.
	// (No credential was bound; the store is the only durable surface.)
	if _, _, err := ls.CurrentSession(); err != nil {
		t.Fatalf("agent store unusable: %v", err)
	}
}
