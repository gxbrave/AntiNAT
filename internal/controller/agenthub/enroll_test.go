// P08 Story 1 RED: Controller enrollment HTTP surface. The hub issues signed
// challenges and consumes possession-proven requests, replaying the original
// binding result on response loss and failing closed on wrong keys, expired
// tokens, and cross-node/controller reuse.
package agenthub_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/agenthub"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func newTestHub(t *testing.T) (*agenthub.Hub, *store.Store, ed25519.PublicKey) {
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
	return hub, st, kr.PublicKey()
}

func newAgentKey(t *testing.T) *security.NodeKey {
	t.Helper()
	k, err := security.LoadOrCreateNodeKey(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// enrollRound performs the full HTTP enrollment round: challenge then request.
func enrollRound(t *testing.T, h *agenthub.Hub, controllerPub ed25519.PublicKey, nodeID string, token string, key *security.NodeKey) (*protocol.EnrollResult, error) {
	t.Helper()
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// 1. Challenge.
	chalResp, err := http.Post(srv.URL+"/agent/v1/enroll/challenge", "application/octet-stream",
		bytes.NewReader([]byte(nodeID)))
	if err != nil {
		t.Fatalf("challenge POST: %v", err)
	}
	defer chalResp.Body.Close()
	if chalResp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(chalResp.Body)
		return nil, errors.New("challenge status " + chalResp.Status)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(chalResp.Body)
	chalBytes := buf.Bytes()
	chal, err := protocol.ParseEnrollChallenge(chalBytes, controllerPub)
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	// The wire node id is zero-padded to 16 bytes; compare the unpadded form.
	if got := strings.TrimRight(string(chal.NodeID[:]), "\x00"); got != nodeID {
		t.Fatalf("challenge node = %q, want %q", got, nodeID)
	}

	// 2. Request. challenge_hash is sha256 of the CANONICAL challenge
	// (protocol.md §4.2 field 1: "sha256 of the canonical EnrollChallenge"),
	// i.e. the wire bytes minus the trailing signature.
	canonical := chalBytes[:len(chalBytes)-64]
	chash := sha256.Sum256(canonical)
	var agentNonce [protocol.EnrollNonceSize]byte
	rand.Read(agentNonce[:])
	req := protocol.EnrollRequest{
		ChallengeHash:          chash,
		AgentNonce:             agentNonce,
		AgentPublicKey:         [32]byte(key.PublicKey()),
		AgentCredentialVersion: key.CredentialVersion(),
		Token:                  token,
		CapabilityHash:         sha256.Sum256([]byte("capabilities-v1")),
	}
	sig, err := key.Sign(req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	reqBytes := append(req.Canonical(), sig...)
	reqResp, err := http.Post(srv.URL+"/agent/v1/enroll/request", "application/octet-stream",
		bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("request POST: %v", err)
	}
	defer reqResp.Body.Close()
	if reqResp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(reqResp.Body)
		return nil, errors.New("request status " + reqResp.Status + ": " + buf.String())
	}
	buf = new(bytes.Buffer)
	buf.ReadFrom(reqResp.Body)
	res, err := protocol.ParseEnrollResult(buf.Bytes(), controllerPub)
	if err != nil {
		t.Fatalf("parse result: %v", err)
	}
	return &res, nil
}

// RED 1s: the happy-path enrollment round binds the credential and returns a
// signed EnrollResult carrying the result id and credential version.
func TestEnrollHappyPath(t *testing.T) {
	hub, st, pub := newTestHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	key := newAgentKey(t)
	res, err := enrollRound(t, hub, pub, nodeID, token, key)
	if err != nil {
		t.Fatalf("enroll round: %v", err)
	}
	if res.AgentCredentialVersion != 1 {
		t.Fatalf("credential version = %d, want 1", res.AgentCredentialVersion)
	}
	cred, err := st.NodeCredentialByNode(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	ph := key.PublicKeyHash()
	wantHash := hex.EncodeToString(ph[:])
	if cred.PublicKeyHash != wantHash {
		t.Fatalf("bound public key hash = %q, want %q", cred.PublicKeyHash, wantHash)
	}
}

// RED 1t: response loss — repeating the request with a fresh challenge and
// the same node/key/possession returns the ORIGINAL result id, and no second
// token is consumed.
func TestEnrollResponseLossReplaysOriginalResult(t *testing.T) {
	hub, st, pub := newTestHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	key := newAgentKey(t)
	first, err := enrollRound(t, hub, pub, nodeID, token, key)
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// The token was consumed; a replayed request with the same key and a
	// fresh challenge must return the original result even with a stale token.
	second, err := enrollRound(t, hub, pub, nodeID, token, key)
	if err != nil {
		t.Fatalf("replayed enroll: %v", err)
	}
	if second.EnrollmentResultID != first.EnrollmentResultID {
		t.Fatalf("replayed result id = %x, want original %x", second.EnrollmentResultID, first.EnrollmentResultID)
	}
}

// RED 1u: a request signed by a DIFFERENT possession key (not the key in the
// request) fails closed.
func TestEnrollWrongPossessionKeyRejected(t *testing.T) {
	hub, st, _ := newTestHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	key := newAgentKey(t)

	srv := httptest.NewServer(hub.Handler())
	defer srv.Close()
	chalResp, err := http.Post(srv.URL+"/agent/v1/enroll/challenge", "application/octet-stream",
		bytes.NewReader([]byte(nodeID)))
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(chalResp.Body)
	chalResp.Body.Close()
	chalBytes := buf.Bytes()

	// Build the request with key A but sign with a forged key B.
	forged, _ := security.LoadOrCreateNodeKey(t.TempDir(), 1)
	var agentNonce [protocol.EnrollNonceSize]byte
	rand.Read(agentNonce[:])
	req := protocol.EnrollRequest{
		ChallengeHash:          sha256.Sum256(chalBytes),
		AgentNonce:             agentNonce,
		AgentPublicKey:         [32]byte(key.PublicKey()),
		AgentCredentialVersion: key.CredentialVersion(),
		Token:                  token,
		CapabilityHash:         sha256.Sum256([]byte("capabilities-v1")),
	}
	sig, err := forged.Sign(req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	reqResp, err := http.Post(srv.URL+"/agent/v1/enroll/request", "application/octet-stream",
		bytes.NewReader(append(req.Canonical(), sig...)))
	if err != nil {
		t.Fatal(err)
	}
	defer reqResp.Body.Close()
	if reqResp.StatusCode == http.StatusOK {
		t.Fatal("wrong-possession request accepted")
	}
}

// RED 1v: an expired token is rejected with a 4xx and no binding.
func TestEnrollExpiredTokenRejected(t *testing.T) {
	hub, st, pub := newTestHub(t)
	nodeID := "node-a"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken(nodeID, -1) // expired
	if err != nil {
		t.Fatal(err)
	}
	key := newAgentKey(t)
	if _, err := enrollRound(t, hub, pub, nodeID, token, key); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := st.NodeCredentialByNode(nodeID); !errors.Is(err, store.ErrNodeNotFound) {
		t.Fatalf("credential bound despite expired token: %v", err)
	}
}

// RED 1w: cross-node use — a token bound to node A cannot enroll node B.
func TestEnrollCrossNodeRejected(t *testing.T) {
	hub, st, pub := newTestHub(t)
	if err := st.CreateNode(store.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateNode(store.Node{ID: "node-b", Name: "node-b"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	key := newAgentKey(t)
	if _, err := enrollRound(t, hub, pub, "node-b", token, key); err == nil {
		t.Fatal("cross-node enrollment accepted")
	}
}

// RED 1x: plaintext public enrollment is refused by default — a
// non-loopback remote without TLS gets 403 (Story 6 boundary, exercised here
// because the enroll handler is the enforcement point).
func TestEnrollPlaintextPublicRefused(t *testing.T) {
	hub, st, _ := newTestHub(t)
	if err := st.CreateNode(store.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	// Drive the handler directly with a crafted request whose RemoteAddr is a
	// public literal (httptest always dials loopback, so the policy must be
	// exercised on the request the handler actually sees).
	req, err := http.NewRequest(http.MethodPost, "http://controller.invalid/agent/v1/enroll/challenge",
		bytes.NewReader([]byte("node-a")))
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.9:40000" // TEST-NET-3 public literal
	rec := httptest.NewRecorder()
	hub.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plaintext public enroll status = %d, want 403", rec.Code)
	}
	// Loopback plaintext remains allowed (localhost installs).
	req2, err := http.NewRequest(http.MethodPost, "http://controller.invalid/agent/v1/enroll/challenge",
		bytes.NewReader([]byte("node-a")))
	if err != nil {
		t.Fatal(err)
	}
	req2.RemoteAddr = "127.0.0.1:40001"
	rec2 := httptest.NewRecorder()
	hub.Handler().ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusForbidden {
		t.Fatal("loopback plaintext enrollment refused")
	}
}

// RED 1y: an unknown node (no row) is rejected at the challenge stage.
func TestEnrollUnknownNodeRejected(t *testing.T) {
	hub, _, _ := newTestHub(t)
	srv := httptest.NewServer(hub.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/agent/v1/enroll/challenge", "application/octet-stream",
		bytes.NewReader([]byte("ghost-node")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("challenge issued for unknown node")
	}
}
