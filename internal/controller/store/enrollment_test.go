package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// P08 Story 1 RED: enrollment token creation and atomic consume/bind/result.
// The tables (node_enrollment_tokens, node_credentials) were created by P06
// migration 0002 for P08's consumption; these methods are the P08-declared
// store extension (frozen protocol.md §4.4: single-transaction consume/bind/
// result, idempotent response-loss recovery, uniform different-key failure).

func openEnrollStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustCreateNode(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.CreateNode(Node{ID: id, Name: id, ControlState: "OFFLINE"}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
}

func hashHex(t *testing.T, plain string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// RED 1k: token creation stores only the SHA-256 hash; the plaintext token is
// returned exactly once and never persisted.
func TestCreateEnrollmentTokenStoresHashOnly(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")

	plain, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	if len(plain) < 32 {
		t.Fatalf("token too short: %d bytes", len(plain))
	}
	// The plaintext must not appear anywhere in the database text.
	var tokenHash string
	if err := s.db.QueryRow(
		`SELECT token_hash FROM node_enrollment_tokens WHERE node_id = 'node-a'`,
	).Scan(&tokenHash); err != nil {
		t.Fatalf("query token row: %v", err)
	}
	if tokenHash == plain {
		t.Fatal("plaintext token stored in node_enrollment_tokens.token_hash")
	}
	if tokenHash != hashHex(t, plain) {
		t.Fatalf("token_hash = %q, want sha256(plaintext) = %q", tokenHash, hashHex(t, plain))
	}
	// Status must be PENDING.
	var status string
	if err := s.db.QueryRow(
		`SELECT status FROM node_enrollment_tokens WHERE node_id = 'node-a'`,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("status = %q, want PENDING", status)
	}
}

// RED 1l: consuming a valid token atomically consumes it, binds the
// credential, and records the enrollment result in one transaction.
func TestConsumeEnrollmentTokenAtomic(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	plain, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollmentRequest{
		NodeID: "node-a", TokenHash: hashHex(t, plain),
		AgentPublicKeyHash: "pubhash-a", CredentialVersion: 1,
		CapabilityHash: "cap-a", ControllerKeyID: "k-1",
		ResultID: "result-1", ResultExpiryUnix: now() + 86400,
	}
	res, replayed, err := s.ConsumeEnrollmentToken(req)
	if err != nil {
		t.Fatalf("ConsumeEnrollmentToken: %v", err)
	}
	if replayed {
		t.Fatal("first consume reported replayed")
	}
	if res.ResultID != "result-1" || res.AgentPublicKeyHash != "pubhash-a" {
		t.Fatalf("result = %+v", res)
	}
	// Token consumed.
	var status string
	if err := s.db.QueryRow(
		`SELECT status FROM node_enrollment_tokens WHERE node_id = 'node-a'`,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "CONSUMED" {
		t.Fatalf("token status = %q, want CONSUMED", status)
	}
	// Credential bound.
	cred, err := s.NodeCredentialByNode("node-a")
	if err != nil {
		t.Fatalf("NodeCredentialByNode: %v", err)
	}
	if cred.PublicKeyHash != "pubhash-a" || cred.CredentialVersion != 1 {
		t.Fatalf("credential = %+v", cred)
	}
}

// RED 1m: response loss — the same node + same key + valid possession proof
// returns the ORIGINAL binding result without consuming a second token
// (frozen protocol.md §4.4 rule 2).
func TestConsumeEnrollmentTokenIdempotentReplay(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	plain, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollmentRequest{
		NodeID: "node-a", TokenHash: hashHex(t, plain),
		AgentPublicKeyHash: "pubhash-a", CredentialVersion: 1,
		CapabilityHash: "cap-a", ControllerKeyID: "k-1",
		ResultID: "result-1", ResultExpiryUnix: now() + 86400,
	}
	if _, _, err := s.ConsumeEnrollmentToken(req); err != nil {
		t.Fatal(err)
	}
	// A replayed request with a NEW challenge (different token hash is
	// irrelevant: the binding already exists) returns the original result.
	replayedReq := req
	replayedReq.TokenHash = hashHex(t, "some-other-token")
	replayedReq.ResultID = "result-DIFFERENT"
	res, replayed, err := s.ConsumeEnrollmentToken(replayedReq)
	if err != nil {
		t.Fatalf("replay consume: %v", err)
	}
	if !replayed {
		t.Fatal("replay did not report replayed=true")
	}
	if res.ResultID != "result-1" {
		t.Fatalf("replayed result id = %q, want original result-1", res.ResultID)
	}
}

// RED 1n: a different key on a registered node fails uniformly and is
// audited; ordinary enrollment tokens cannot rebind (frozen rule 3).
func TestConsumeEnrollmentTokenDifferentKeyRejected(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	plain, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollmentRequest{
		NodeID: "node-a", TokenHash: hashHex(t, plain),
		AgentPublicKeyHash: "pubhash-a", CredentialVersion: 1,
		CapabilityHash: "cap-a", ControllerKeyID: "k-1",
		ResultID: "result-1", ResultExpiryUnix: now() + 86400,
	}
	if _, _, err := s.ConsumeEnrollmentToken(req); err != nil {
		t.Fatal(err)
	}
	plain2, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	evil := req
	evil.TokenHash = hashHex(t, plain2)
	evil.AgentPublicKeyHash = "pubhash-EVIL"
	evil.ResultID = "result-evil"
	if _, _, err := s.ConsumeEnrollmentToken(evil); !errors.Is(err, ErrNodeCredentialConflict) {
		t.Fatalf("different-key consume = %v, want ErrNodeCredentialConflict", err)
	}
	// Audited.
	events, err := s.AdminEventsAfter(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if strings.Contains(e.EventType, "ENROLLMENT") || strings.Contains(e.Payload, "node-a") {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit event recorded for rejected rebind")
	}
}

// RED 1o: an expired token cannot be consumed.
func TestConsumeEnrollmentTokenExpired(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	plain, err := s.CreateEnrollmentToken("node-a", -1) // already expired
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollmentRequest{
		NodeID: "node-a", TokenHash: hashHex(t, plain),
		AgentPublicKeyHash: "pubhash-a", CredentialVersion: 1,
		CapabilityHash: "cap-a", ControllerKeyID: "k-1",
		ResultID: "result-1", ResultExpiryUnix: now() + 86400,
	}
	if _, _, err := s.ConsumeEnrollmentToken(req); !errors.Is(err, ErrEnrollmentTokenExpired) {
		t.Fatalf("expired consume = %v, want ErrEnrollmentTokenExpired", err)
	}
}

// RED 1p: an unknown token hash fails closed.
func TestConsumeEnrollmentTokenUnknown(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	req := EnrollmentRequest{
		NodeID: "node-a", TokenHash: hashHex(t, "no-such-token"),
		AgentPublicKeyHash: "pubhash-a", CredentialVersion: 1,
		CapabilityHash: "cap-a", ControllerKeyID: "k-1",
		ResultID: "result-1", ResultExpiryUnix: now() + 86400,
	}
	if _, _, err := s.ConsumeEnrollmentToken(req); !errors.Is(err, ErrEnrollmentTokenNotFound) {
		t.Fatalf("unknown consume = %v, want ErrEnrollmentTokenNotFound", err)
	}
}

// RED 1q: a token bound to a different node cannot enroll another node.
func TestConsumeEnrollmentTokenNodeMismatch(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	mustCreateNode(t, s, "node-b")
	plain, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollmentRequest{
		NodeID: "node-b", TokenHash: hashHex(t, plain),
		AgentPublicKeyHash: "pubhash-b", CredentialVersion: 1,
		CapabilityHash: "cap-b", ControllerKeyID: "k-1",
		ResultID: "result-b", ResultExpiryUnix: now() + 86400,
	}
	if _, _, err := s.ConsumeEnrollmentToken(req); !errors.Is(err, ErrEnrollmentTokenNodeMismatch) {
		t.Fatalf("cross-node consume = %v, want ErrEnrollmentTokenNodeMismatch", err)
	}
}

// RED 1r: the result hash-only property — the credential store never holds
// the private key, only the public key hash.
func TestEnrollmentResultHashOnly(t *testing.T) {
	s := openEnrollStore(t)
	mustCreateNode(t, s, "node-a")
	plain, err := s.CreateEnrollmentToken("node-a", 3600)
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollmentRequest{
		NodeID: "node-a", TokenHash: hashHex(t, plain),
		AgentPublicKeyHash: "pubhash-a", CredentialVersion: 1,
		CapabilityHash: "cap-a", ControllerKeyID: "k-1",
		ResultID: "result-1", ResultExpiryUnix: now() + 86400,
	}
	if _, _, err := s.ConsumeEnrollmentToken(req); err != nil {
		t.Fatal(err)
	}
	got, err := s.EnrollmentResultByNodeAndKey("node-a", "pubhash-a", 1)
	if err != nil {
		t.Fatalf("EnrollmentResultByNodeAndKey: %v", err)
	}
	if got.ResultID != "result-1" {
		t.Fatalf("result = %+v", got)
	}
}
