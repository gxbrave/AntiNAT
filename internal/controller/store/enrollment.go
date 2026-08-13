package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// P08-owned store extension: enrollment tokens, credential binding, and
// enrollment results (frozen protocol.md §4.4). The tables were created by
// P06 migration 0002 for P08's consumption; every rule here mirrors the
// frozen contract:
//
//  1. Token consumption, credential binding, and enrollment result ID are
//     committed in a single SQLite transaction.
//  2. If the EnrollResult response is lost, the same node + same key + valid
//     possession proof returns the original binding result (idempotent).
//  3. A different key on a registered node fails uniformly and is audited;
//     ordinary enrollment tokens cannot rebind a registered node's key.
//  4. Tokens are stored only as SHA-256 hashes and never appear in logs.

// Enrollment errors — stable sentinels for the enrollment HTTP layer.
var (
	// ErrEnrollmentTokenNotFound reports an unknown token hash.
	ErrEnrollmentTokenNotFound = errors.New("store: enrollment token not found")
	// ErrEnrollmentTokenExpired reports a consumed-token attempt past expiry.
	ErrEnrollmentTokenExpired = errors.New("store: enrollment token expired")
	// ErrEnrollmentTokenConsumed reports a token already consumed.
	ErrEnrollmentTokenConsumed = errors.New("store: enrollment token already consumed")
	// ErrEnrollmentTokenNodeMismatch reports a token bound to another node.
	ErrEnrollmentTokenNodeMismatch = errors.New("store: enrollment token node mismatch")
	// ErrNodeCredentialConflict reports a registered node trying to bind a
	// different key (frozen §4.4 rule 3: uniform failure + audit).
	ErrNodeCredentialConflict = errors.New("store: node already bound to a different credential")
	// ErrEnrollmentResultNotFound reports a missing durable enrollment result.
	ErrEnrollmentResultNotFound = errors.New("store: enrollment result not found")
)

// EnrollmentRequest carries the atomic consume/bind/result inputs.
type EnrollmentRequest struct {
	NodeID             string
	TokenHash          string
	AgentPublicKeyHash string
	CredentialVersion  uint32
	CapabilityHash     string
	ControllerKeyID    string
	ResultID           string
	ResultExpiryUnix   int64
}

// EnrollmentResult is the durable binding result (frozen §4.3 fields).
type EnrollmentResult struct {
	ResultID           string
	NodeID             string
	AgentPublicKeyHash string
	CredentialVersion  uint32
	ControllerKeyID    string
	CapabilityHash     string
	ExpiryUnix         int64
	CreatedAt          int64
}

// NodeCredential is the bound Agent credential row.
type NodeCredential struct {
	NodeID            string
	KeyType           string
	PublicKeyHash     string
	CredentialVersion uint32
	CreatedAt         int64
}

// newID returns a fresh 16-byte hex id (the store's TEXT id convention).
func newID() (string, error) {
	return randomHex(16)
}

// CreateEnrollmentToken generates a fresh one-time enrollment token bound to
// nodeID. Only the SHA-256 hash is persisted; the plaintext is returned
// exactly once to the caller (the admin flow hands it to the operator; it is
// never stored or logged).
func (s *Store) CreateEnrollmentToken(nodeID string, ttlSeconds int64) (string, error) {
	if err := s.checkWriteCapacity(); err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: enrollment token rand: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	ts := now()
	id, err := newID()
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(
		`INSERT INTO node_enrollment_tokens
		    (id, token_hash, node_id, status, expires_at, created_at)
		 VALUES (?, ?, ?, 'PENDING', ?, ?)`,
		id, hex.EncodeToString(sum[:]), nodeID, ts+ttlSeconds, ts,
	); err != nil {
		return "", fmt.Errorf("store: insert enrollment token: %w", err)
	}
	return plain, nil
}

// ConsumeEnrollmentToken implements the frozen atomic enrollment transaction.
// It returns the effective binding result and whether the request was
// replayed from a prior binding (response-loss recovery). The read-check-write
// runs in one BEGIN IMMEDIATE transaction on a dedicated connection so
// concurrent same-node enrollments serialize (same pattern as idempotency).
func (s *Store) ConsumeEnrollmentToken(req EnrollmentRequest) (EnrollmentResult, bool, error) {
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: enrollment conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: begin enrollment: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	// Rule 2/3: is the node already registered?
	existing, err := s.nodeCredentialTx(conn, req.NodeID)
	switch {
	case err == nil && existing.PublicKeyHash == req.AgentPublicKeyHash && existing.CredentialVersion == req.CredentialVersion:
		// Same node + same key + possession proof: return the original
		// binding result without consuming another token.
		res, err := s.enrollmentResultTx(conn, req.NodeID, req.AgentPublicKeyHash, req.CredentialVersion)
		if err != nil {
			return EnrollmentResult{}, false, err
		}
		if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return EnrollmentResult{}, false, fmt.Errorf("store: commit enrollment replay: %w", err)
		}
		committed = true
		return res, true, nil
	case err == nil:
		// Rule 3: different key on a registered node — uniform failure + audit.
		if _, err := conn.ExecContext(context.Background(),
			`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
			"ENROLLMENT_REBIND_REJECTED",
			fmt.Sprintf(`{"node_id":%q,"credential_version":%d}`, req.NodeID, req.CredentialVersion),
			now(),
		); err != nil {
			return EnrollmentResult{}, false, fmt.Errorf("store: enrollment rebind audit: %w", err)
		}
		if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return EnrollmentResult{}, false, fmt.Errorf("store: commit enrollment reject: %w", err)
		}
		committed = true
		return EnrollmentResult{}, false, ErrNodeCredentialConflict
	case !errors.Is(err, sql.ErrNoRows):
		return EnrollmentResult{}, false, err
	}

	// Rule 4 + expiry: validate the token.
	var status string
	var expiresAt int64
	var tokenNode string
	err = conn.QueryRowContext(context.Background(),
		`SELECT status, expires_at, node_id FROM node_enrollment_tokens WHERE token_hash = ?`,
		req.TokenHash,
	).Scan(&status, &expiresAt, &tokenNode)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentResult{}, false, ErrEnrollmentTokenNotFound
	}
	if err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: get enrollment token: %w", err)
	}
	if tokenNode != req.NodeID {
		return EnrollmentResult{}, false, ErrEnrollmentTokenNodeMismatch
	}
	if status == "CONSUMED" {
		return EnrollmentResult{}, false, ErrEnrollmentTokenConsumed
	}
	if expiresAt <= now() {
		return EnrollmentResult{}, false, ErrEnrollmentTokenExpired
	}

	// Atomic consume + bind + result (rule 1).
	if _, err := conn.ExecContext(context.Background(),
		`UPDATE node_enrollment_tokens
		    SET status = 'CONSUMED', consumed_at = ?
		  WHERE token_hash = ? AND status = 'PENDING'`,
		now(), req.TokenHash,
	); err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: consume enrollment token: %w", err)
	}
	ts := now()
	credID, err := newID()
	if err != nil {
		return EnrollmentResult{}, false, err
	}
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO node_credentials
		    (id, node_id, key_type, public_key_hash, credential_version, created_at)
		 VALUES (?, ?, 'ed25519', ?, ?, ?)`,
		credID, req.NodeID, req.AgentPublicKeyHash, req.CredentialVersion, ts,
	); err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: bind node credential: %w", err)
	}
	res := EnrollmentResult{
		ResultID:           req.ResultID,
		NodeID:             req.NodeID,
		AgentPublicKeyHash: req.AgentPublicKeyHash,
		CredentialVersion:  req.CredentialVersion,
		ControllerKeyID:    req.ControllerKeyID,
		CapabilityHash:     req.CapabilityHash,
		ExpiryUnix:         req.ResultExpiryUnix,
		CreatedAt:          ts,
	}
	resID, err := newID()
	if err != nil {
		return EnrollmentResult{}, false, err
	}
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO enrollment_results
		    (id, node_id, enrollment_result_id, agent_public_key_hash,
		     credential_version, controller_key_id, capability_hash,
		     expiry_unix, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		resID, req.NodeID, req.ResultID, req.AgentPublicKeyHash,
		req.CredentialVersion, req.ControllerKeyID, req.CapabilityHash,
		req.ResultExpiryUnix, ts,
	); err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: record enrollment result: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO admin_events (event_type, payload, created_at) VALUES (?, ?, ?)`,
		"ENROLLMENT_BOUND",
		fmt.Sprintf(`{"node_id":%q,"result_id":%q,"credential_version":%d}`, req.NodeID, req.ResultID, req.CredentialVersion),
		ts,
	); err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: enrollment bound audit: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return EnrollmentResult{}, false, fmt.Errorf("store: commit enrollment: %w", err)
	}
	committed = true
	return res, false, nil
}

// NodeCredentialByNode returns the bound credential for a node.
func (s *Store) NodeCredentialByNode(nodeID string) (NodeCredential, error) {
	row := s.db.QueryRow(
		`SELECT node_id, key_type, public_key_hash, credential_version, created_at
		   FROM node_credentials WHERE node_id = ?`, nodeID,
	)
	var c NodeCredential
	err := row.Scan(&c.NodeID, &c.KeyType, &c.PublicKeyHash, &c.CredentialVersion, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeCredential{}, ErrNodeNotFound
	}
	if err != nil {
		return NodeCredential{}, fmt.Errorf("store: get node credential: %w", err)
	}
	return c, nil
}

// EnrollmentResultByNodeAndKey returns the durable original binding result
// (idempotent response-loss recovery).
func (s *Store) EnrollmentResultByNodeAndKey(nodeID, pubKeyHash string, version uint32) (EnrollmentResult, error) {
	row := s.db.QueryRow(
		`SELECT enrollment_result_id, node_id, agent_public_key_hash,
		        credential_version, controller_key_id, capability_hash,
		        expiry_unix, created_at
		   FROM enrollment_results
		  WHERE node_id = ? AND agent_public_key_hash = ? AND credential_version = ?`,
		nodeID, pubKeyHash, version,
	)
	return scanEnrollmentResult(row)
}

func (s *Store) nodeCredentialTx(conn *sql.Conn, nodeID string) (NodeCredential, error) {
	var c NodeCredential
	err := conn.QueryRowContext(context.Background(),
		`SELECT node_id, key_type, public_key_hash, credential_version, created_at
		   FROM node_credentials WHERE node_id = ?`, nodeID,
	).Scan(&c.NodeID, &c.KeyType, &c.PublicKeyHash, &c.CredentialVersion, &c.CreatedAt)
	return c, err
}

func (s *Store) enrollmentResultTx(conn *sql.Conn, nodeID, pubKeyHash string, version uint32) (EnrollmentResult, error) {
	row := conn.QueryRowContext(context.Background(),
		`SELECT enrollment_result_id, node_id, agent_public_key_hash,
		        credential_version, controller_key_id, capability_hash,
		        expiry_unix, created_at
		   FROM enrollment_results
		  WHERE node_id = ? AND agent_public_key_hash = ? AND credential_version = ?`,
		nodeID, pubKeyHash, version,
	)
	return scanEnrollmentResult(row)
}

func scanEnrollmentResult(row *sql.Row) (EnrollmentResult, error) {
	var r EnrollmentResult
	err := row.Scan(&r.ResultID, &r.NodeID, &r.AgentPublicKeyHash,
		&r.CredentialVersion, &r.ControllerKeyID, &r.CapabilityHash,
		&r.ExpiryUnix, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentResult{}, ErrEnrollmentResultNotFound
	}
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("store: scan enrollment result: %w", err)
	}
	return r, nil
}
