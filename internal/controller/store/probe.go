// P10-owned store extension: the durable probe provider registry, probe
// operation journal, and the controller-side orthogonal activation mirror
// (migration 0004, frozen docs/protocol.md §7/§8 and docs/state-model.md §1).
// The probe manager consumes these rows; the hub remains transport-only.
package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"errors"
	"fmt"
	"strings"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ProbeProvider is a registered operator-owned probe vantage service. The
// public key verifies signed provider results; the egress IP is the exact
// source the ARM1 frame pins as expected_source_ip.
type ProbeProvider struct {
	ID                 string
	Name               string
	PublicKey          string
	EgressIP           string
	Endpoint           string
	Enabled            bool
	IndependentVantage bool
	CreatedAt          int64
	UpdatedAt          int64
}

// CreateProbeProvider registers a provider. The id is unique.
func (s *Store) CreateProbeProvider(p ProbeProvider) (ProbeProvider, error) {
	ts := now()
	_, err := s.db.Exec(
		`INSERT INTO probe_providers
		    (id, name, public_key, egress_ip, endpoint, enabled, independent_vantage, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.PublicKey, p.EgressIP, p.Endpoint, boolInt(p.Enabled), boolInt(p.IndependentVantage), ts, ts,
	)
	if err != nil {
		return ProbeProvider{}, fmt.Errorf("store: create probe provider: %w", err)
	}
	return s.GetProbeProvider(p.ID)
}

// GetProbeProvider returns a provider by id.
func (s *Store) GetProbeProvider(id string) (ProbeProvider, error) {
	var p ProbeProvider
	var enabled int
	err := s.db.QueryRow(
		`SELECT id, name, public_key, egress_ip, endpoint, enabled, independent_vantage, created_at, updated_at
		   FROM probe_providers WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.PublicKey, &p.EgressIP, &p.Endpoint, &enabled, &p.IndependentVantage, &p.CreatedAt, &p.UpdatedAt)
	p.Enabled = enabled != 0
	if errors.Is(err, sql.ErrNoRows) {
		return ProbeProvider{}, ErrNotFound
	}
	if err != nil {
		return ProbeProvider{}, fmt.Errorf("store: get probe provider: %w", err)
	}
	return p, nil
}

// SetProbeProviderEnabled toggles a provider. Disabled providers are never
// selected for new arms.
func (s *Store) SetProbeProviderEnabled(id string, enabled bool) error {
	res, err := s.db.Exec(
		`UPDATE probe_providers SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolInt(enabled), now(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set probe provider enabled: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe provider rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// SetProbeProviderIndependentVantage changes the operator-owned topology
// declaration. Changing it never changes existing operation evidence.
func (s *Store) SetProbeProviderIndependentVantage(id string, independent bool) error {
	res, err := s.db.Exec(`UPDATE probe_providers SET independent_vantage = ?, updated_at = ? WHERE id = ?`, boolInt(independent), now(), id)
	if err != nil {
		return fmt.Errorf("store: set probe provider independence: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe provider independence rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// ListProbeProviders returns every registered provider.
func (s *Store) ListProbeProviders() ([]ProbeProvider, error) {
	rows, err := s.db.Query(
		`SELECT id, name, public_key, egress_ip, endpoint, enabled, independent_vantage, created_at, updated_at
		   FROM probe_providers ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list probe providers: %w", err)
	}
	defer rows.Close()
	var out []ProbeProvider
	for rows.Next() {
		var p ProbeProvider
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.PublicKey, &p.EgressIP, &p.Endpoint, &enabled, &p.IndependentVantage, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan probe provider: %w", err)
		}
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProbeOperation is one durable probe operation row. Status uses the frozen
// outcome registry (docs/protocol.md §8) plus PENDING/ARMED/IN_FLIGHT
// intermediate states. ArmHex is the canonical ARM1 frame bytes.
type ProbeOperation struct {
	ID           string
	NodeID       string
	ForwardID    string
	ActivationID string
	// ExpectedForwardRevision is the forward generation observed when the
	// operation was armed. Activation identity alone is not a delete fence:
	// online deletion advances revision without rotating the activation.
	ExpectedForwardRevision uint64
	ProviderID              string
	Status                  string
	Endpoint                string
	ArmHex                  string
	ChallengeHash           string
	TTLMS                   uint64
	ExpiryOpaque            string
	ExpiresAt               int64
	CreatedAt               int64
	UpdatedAt               int64
}

// CreateProbeOperation inserts a PENDING operation row.
func (s *Store) CreateProbeOperation(op ProbeOperation) (ProbeOperation, error) {
	ts := s.currentUnix()
	if op.ExpectedForwardRevision == 0 {
		// Legacy/internal fixtures may omit the generation. Recover it only when
		// the parent still exists; missing-parent tombstone fixtures remain
		// representable but cannot pass a publication CAS.
		_ = s.db.QueryRow(`SELECT revision FROM forwards WHERE id = ?`, op.ForwardID).Scan(&op.ExpectedForwardRevision)
	}
	_, err := s.db.Exec(
		`INSERT INTO probe_operations
		    (id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
		     arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, op.ForwardID, op.ActivationID, op.ExpectedForwardRevision, op.ProviderID, orDefault(op.Status, "PENDING"),
		op.Endpoint, op.ArmHex, op.ChallengeHash, op.TTLMS, op.ExpiryOpaque, op.ExpiresAt, ts, ts,
	)
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: create probe operation: %w", err)
	}
	return s.GetProbeOperation(op.ID)
}

// CreateProbeOperationBundle atomically records the operation and its probe_arm
// command. A store failure cannot leave an arm without its durable intent or
// leave an intent that the outbox cannot retry.
func (s *Store) CreateProbeOperationBundle(op ProbeOperation, outbox ControlOutboxItem) (ProbeOperation, error) {
	// Arm creation is a read-then-write CAS against the forward and deletion
	// intent. Reserve the writer before reading so concurrent control-plane
	// writers cannot invalidate the snapshot and surface SQLITE_BUSY_SNAPSHOT.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: probe bundle conn: %w", err)
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: begin probe bundle: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	ts := s.currentUnix()
	// Bind the durable arm to the forward's current activation at the same
	// transaction boundary as the operation/outbox insert. The Manager checks
	// this before provider selection as a fast path, but this CAS is the actual
	// race fence when an activation changes between those two steps.
	var forwardNodeID, currentActivationID sql.NullString
	var currentRevision uint64
	if err := conn.QueryRowContext(ctx, `SELECT node_id, current_activation_id, revision FROM forwards WHERE id = ?`, op.ForwardID).
		Scan(&forwardNodeID, &currentActivationID, &currentRevision); errors.Is(err, sql.ErrNoRows) {
		return ProbeOperation{}, ErrForwardNotFound
	} else if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: read probe bundle forward: %w", err)
	}
	if !forwardNodeID.Valid || forwardNodeID.String != op.NodeID {
		return ProbeOperation{}, fmt.Errorf("%w: operation/forward node mismatch", ErrCASConflict)
	}
	if !currentActivationID.Valid || currentActivationID.String == "" || currentActivationID.String != op.ActivationID {
		return ProbeOperation{}, ErrCASConflict
	}
	if op.ExpectedForwardRevision == 0 || currentRevision != op.ExpectedForwardRevision {
		return ProbeOperation{}, ErrCASConflict
	}
	var deletionIntent int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM forward_deletion_operations WHERE forward_id = ? AND status = 'PENDING')`, op.ForwardID).Scan(&deletionIntent); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: read probe bundle deletion intent: %w", err)
	}
	if deletionIntent != 0 {
		return ProbeOperation{}, ErrCASConflict
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO probe_operations
		(id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
		 arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, op.ForwardID, op.ActivationID, op.ExpectedForwardRevision, op.ProviderID, orDefault(op.Status, "PENDING"),
		op.Endpoint, op.ArmHex, op.ChallengeHash, op.TTLMS, op.ExpiryOpaque, op.ExpiresAt, ts, ts); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: probe bundle operation: %w", err)
	}
	if err := insertOutboxExec(ctx, conn, outbox); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: probe bundle outbox: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: commit probe bundle: %w", err)
	}
	committed = true
	return s.GetProbeOperation(op.ID)
}

// GetProbeOperation returns an operation row by probe id.
func (s *Store) GetProbeOperation(id string) (ProbeOperation, error) {
	var op ProbeOperation
	err := s.db.QueryRow(
		`SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
		        arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		   FROM probe_operations WHERE id = ?`, id,
	).Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status,
		&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
		&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProbeOperation{}, ErrNotFound
	}
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: get probe operation: %w", err)
	}
	return op, nil
}

var (
	ErrProbeIllegalTransition = errors.New("store: illegal probe operation transition")
	ErrProbeTerminal          = errors.New("store: probe operation is terminal")
	ErrProbeExpired           = errors.New("store: probe operation has expired")
	ErrProbeDuplicateEvidence = errors.New("store: duplicate probe evidence")
	ErrProbeJoinIncomplete    = errors.New("store: probe join evidence is incomplete")
	ErrProbeJoinRequired      = errors.New("store: OPEN_FROM_VANTAGE requires a complete probe join")
	ErrProbeChallengeConflict = errors.New("store: probe challenge evidence conflicts")
	ErrProbeLookupBudget      = errors.New("store: probe lookup budget exhausted")
	ErrProbeAmbiguous         = errors.New("store: probe arm digest matches multiple live operations")
	ErrProbeCorrupt           = errors.New("store: persisted probe operation is corrupt")
)

func probeTerminal(status string) bool {
	switch status {
	case string(protocol.OutcomeOpenFromVantage), string(protocol.OutcomeRejected),
		string(protocol.OutcomeDropped), string(protocol.OutcomeTimeout),
		string(protocol.OutcomeNoIndependentVantage), string(protocol.OutcomeProbeInfraUnavailable):
		return true
	default:
		return false
	}
}

func probeTransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	if probeTerminal(from) {
		return false
	}
	switch from {
	case "PENDING":
		return to == "ARMED" || probeTerminal(to)
	case "ARMED":
		return to == "IN_FLIGHT" || probeTerminal(to)
	case "IN_FLIGHT":
		return probeTerminal(to)
	default:
		return false
	}
}

// SetProbeOperationStatus advances an operation through the frozen probe
// lifecycle. Terminal rows cannot be reopened or rewritten.
func (s *Store) SetProbeOperationStatus(id, status string) error {
	return s.setProbeOperationStatusCAS(id, "", status)
}

// SetProbeOperationStatusCAS advances an operation only when its current
// status equals expected. It is the join fence: late artifacts cannot reopen
// a timed-out/rejected operation.
func (s *Store) SetProbeOperationStatusCAS(id, expected, status string) error {
	return s.setProbeOperationStatusCAS(id, expected, status)
}

// RequeueProbeOperationForRecovery reopens only an interrupted provider
// request. It is intentionally separate from the public lifecycle CAS: a
// process restart must be able to recover IN_FLIGHT work, while ordinary late
// evidence must never reopen a terminal row.
func (s *Store) RequeueProbeOperationForRecovery(id string) error {
	nowUnix := s.currentUnix()
	res, err := s.db.Exec(`UPDATE probe_operations SET status = 'ARMED', updated_at = ?
		WHERE id = ? AND status = 'IN_FLIGHT' AND expires_at > ?`, nowUnix, id, nowUnix)
	if err != nil {
		return fmt.Errorf("store: requeue probe operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: requeue probe operation rows: %w", err)
	} else if n != 1 {
		return ErrCASConflict
	}
	return nil
}

func (s *Store) setProbeOperationStatusCAS(id, expected, status string) error {
	// Reserve the SQLite writer before reading the row. A deferred transaction
	// can read a snapshot that becomes stale while the AgentHub outbox pump or
	// another lifecycle writer commits, surfacing SQLITE_BUSY_SNAPSHOT on CAS.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("store: probe status conn: %w", err)
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin probe status: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var current string
	var expiresAt int64
	if err := conn.QueryRowContext(ctx, `SELECT status, expires_at FROM probe_operations WHERE id = ?`, id).Scan(&current, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read probe status: %w", err)
	}
	if expected != "" && current != expected {
		if probeTerminal(current) {
			return ErrProbeTerminal
		}
		return ErrCASConflict
	}
	if probeTerminal(current) && current != status {
		return ErrProbeTerminal
	}
	if status == string(protocol.OutcomeOpenFromVantage) {
		return ErrProbeJoinRequired
	}
	if !probeTransitionAllowed(current, status) {
		if current == status {
			return nil
		}
		return fmt.Errorf("%w: %s -> %s", ErrProbeIllegalTransition, current, status)
	}
	if current == status {
		return nil
	}
	nowUnix := s.currentUnix()
	if expiresAt <= nowUnix && status != string(protocol.OutcomeTimeout) {
		return ErrProbeExpired
	}
	res, err := conn.ExecContext(ctx, `UPDATE probe_operations SET status = ?, updated_at = ?
		WHERE id = ? AND status = ?`, status, nowUnix, id, current)
	if err != nil {
		return fmt.Errorf("store: set probe operation status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe operation status rows: %w", err)
	} else if n != 1 {
		return ErrCASConflict
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit probe status: %w", err)
	}
	committed = true
	return nil
}

// SetProbeOperationChallenge records the joined challenge hash while the
// operation is still live. A terminal/expired row cannot be rewritten by a
// late provider response.
func (s *Store) SetProbeOperationChallenge(id, challengeHash string) error {
	// Acquire the writer reservation before reading the operation. A deferred
	// read snapshot can become SQLITE_BUSY_SNAPSHOT when a concurrent joiner
	// commits before this challenge write; that storage race must remain
	// retryable rather than being mistaken for conflicting evidence.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("store: probe challenge conn: %w", err)
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin probe challenge: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	ts := s.currentUnix()
	var status, existing string
	var expiresAt int64
	if err := conn.QueryRowContext(ctx, `SELECT status, challenge_hash, expires_at FROM probe_operations WHERE id = ?`, id).
		Scan(&status, &existing, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read probe operation challenge: %w", err)
	}
	if probeTerminal(status) {
		return ErrProbeTerminal
	}
	if expiresAt <= ts {
		return ErrProbeExpired
	}
	if existing != "" && !strings.EqualFold(existing, challengeHash) {
		return ErrProbeChallengeConflict
	}
	decodedChallenge, decodeErr := hex.DecodeString(challengeHash)
	if decodeErr != nil || len(decodedChallenge) != protocol.ProbeDigestLen {
		return fmt.Errorf("%w: challenge hash must be exactly %d bytes of hexadecimal", ErrProbeJoinIncomplete, protocol.ProbeDigestLen)
	}
	// Store one canonical representation so later comparisons cannot be
	// bypassed by casing. The final join boundary additionally requires the
	// provider challenge hash to decode to the protocol's 32-byte digest.
	challengeHash = strings.ToLower(challengeHash)
	res, err := conn.ExecContext(ctx, `UPDATE probe_operations SET challenge_hash = ?, updated_at = ?
		WHERE id = ? AND status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?`,
		challengeHash, ts, id, ts)
	if err != nil {
		return fmt.Errorf("store: set probe operation challenge: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe operation challenge rows: %w", err)
	} else if n != 1 {
		return ErrProbeTerminal
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit probe challenge: %w", err)
	}
	committed = true
	return nil
}

var activationSnapshotJSONSchema = map[string]protocol.FieldKind{
	"control_state":          protocol.KindString,
	"listener_state":         protocol.KindString,
	"mapping_state":          protocol.KindString,
	"keepalive_state":        protocol.KindString,
	"wan_reachability_state": protocol.KindString,
	"return_path_state":      protocol.KindString,
	"target_health_state":    protocol.KindString,
	"publication_state":      protocol.KindString,
	"data_plane_state":       protocol.KindString,
}

func decodeActivationSnapshot(snapshotJSON string) (protocol.ActivationStates, error) {
	var snapshot protocol.ActivationStates
	if err := protocol.DecodeStrictJSONInto([]byte(snapshotJSON), &snapshot); err != nil {
		return snapshot, err
	}
	if err := snapshot.Validate(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

type storedProviderResult struct {
	Schema        string `json:"schema"`
	ProbeID       string `json:"probe_id"`
	Accepted      bool   `json:"accepted"`
	ChallengeHash string `json:"challenge_hash"`
	WAN1Frame     string `json:"wan1_frame"`
	ACK1Frame     string `json:"ack1_frame"`
	Reason        string `json:"reason"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Signature     string `json:"signature"`
}

var storedProviderResultJSONSchema = map[string]protocol.FieldKind{
	"schema":         protocol.KindString,
	"probe_id":       protocol.KindString,
	"accepted":       protocol.KindBool,
	"challenge_hash": protocol.KindString,
	"wan1_frame":     protocol.KindString,
	"ack1_frame":     protocol.KindString,
	"reason":         protocol.KindString,
	"timestamp_unix": protocol.KindInt,
	"signature":      protocol.KindString,
}

func decodeStoredProviderResult(payload string) (storedProviderResult, error) {
	var result storedProviderResult
	if err := protocol.DecodeStrictJSONInto([]byte(payload), &result); err != nil {
		return result, err
	}
	if result.Schema != "antinat.provider-result/v1" || result.ProbeID == "" || !result.Accepted ||
		result.ChallengeHash == "" || result.WAN1Frame == "" || result.ACK1Frame == "" ||
		result.TimestampUnix <= 0 || result.Signature == "" {
		return result, errors.New("store: incomplete provider result")
	}
	return result, nil
}

func (r storedProviderResult) canonical() []byte {
	fields := []string{
		r.Schema, strings.ToLower(r.ProbeID), fmt.Sprintf("%t", r.Accepted),
		strings.ToLower(r.ChallengeHash), strings.ToLower(r.WAN1Frame),
		strings.ToLower(r.ACK1Frame), r.Reason, fmt.Sprintf("%d", r.TimestampUnix),
	}
	return []byte(strings.Join(fields, "\x00"))
}

func (r storedProviderResult) verify(publicKeyHex string) bool {
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(r.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), r.canonical(), signature)
}

// probeJoinTx is a dedicated connection with an IMMEDIATE transaction. A
// deferred transaction can take a read snapshot and later fail with
// SQLITE_BUSY when it upgrades to a writer after another joiner commits. The
// join boundary must acquire its writer reservation before reading evidence so
// contention waits under the configured busy timeout instead of becoming a
// false lifecycle decision.
type probeJoinTx struct {
	conn *sql.Conn
	done bool
}

func (tx *probeJoinTx) QueryRow(query string, args ...any) *sql.Row {
	return tx.conn.QueryRowContext(context.Background(), query, args...)
}

func (tx *probeJoinTx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.conn.ExecContext(context.Background(), query, args...)
}

func (tx *probeJoinTx) Commit() error {
	if tx.done {
		return nil
	}
	_, err := tx.conn.ExecContext(context.Background(), "COMMIT")
	if err == nil {
		tx.done = true
	}
	return err
}

func (tx *probeJoinTx) Rollback() error {
	if tx.done {
		return nil
	}
	_, err := tx.conn.ExecContext(context.Background(), "ROLLBACK")
	tx.done = true
	return err
}

func (tx *probeJoinTx) Close() error {
	return tx.conn.Close()
}

func (s *Store) beginProbeJoinTx() (*probeJoinTx, error) {
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("store: probe join conn: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("store: begin probe join: %w", err)
	}
	return &probeJoinTx{conn: conn}, nil
}

// PublishProbeJoin atomically transitions the operation to OPEN_FROM_VANTAGE
// and persists its legal activation mirror. Observers can never see an OPEN
// operation without its corresponding frozen snapshot.
func (s *Store) PublishProbeJoin(operationID, expectedStatus, forwardID, activationID, snapshotJSON string, nodePublicKeys ...ed25519.PublicKey) error {
	if _, err := decodeActivationSnapshot(snapshotJSON); err != nil {
		return fmt.Errorf("%w: illegal activation snapshot: %v", ErrProbeJoinIncomplete, err)
	}
	if expectedStatus != "IN_FLIGHT" {
		return fmt.Errorf("%w: expected status must be IN_FLIGHT", ErrProbeIllegalTransition)
	}
	// ACK1 and RCT1 are both node-authenticated frames. The store must not
	// treat a non-zero signature as evidence: callers must provide the
	// authenticated session public key so the final durable CAS can verify both
	// frames again, independently of the in-memory Manager checks. The
	// variadic form preserves source compatibility for older internal callers;
	// omission deliberately fails closed.
	if len(nodePublicKeys) != 1 || len(nodePublicKeys[0]) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: node public key is required to verify ACK1 and RCT1", ErrProbeJoinIncomplete)
	}
	nodePublicKey := nodePublicKeys[0]
	tx, err := s.beginProbeJoinTx()
	if err != nil {
		return err
	}
	defer tx.Close()
	defer tx.Rollback()
	var current, storedForwardID, storedActivationID, providerID, providerPublicKey, storedEndpoint, storedExpiryOpaque, operationArmHex string
	var expiresAt, createdAt int64
	var storedTTLMS, expectedForwardRevision uint64
	if err := tx.QueryRow(`SELECT status, forward_id, activation_id, expected_forward_revision, expires_at, created_at, provider_id,
		endpoint, ttl_ms, expiry_opaque, arm_hex
		FROM probe_operations WHERE id = ?`, operationID).Scan(&current, &storedForwardID, &storedActivationID, &expectedForwardRevision, &expiresAt, &createdAt, &providerID,
		&storedEndpoint, &storedTTLMS, &storedExpiryOpaque, &operationArmHex); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read probe join status: %w", err)
	}
	if current != expectedStatus {
		if probeTerminal(current) {
			return ErrProbeTerminal
		}
		return ErrCASConflict
	}
	if storedForwardID != forwardID || storedActivationID != activationID {
		return fmt.Errorf("%w: operation binding mismatch", ErrProbeJoinIncomplete)
	}
	if err := tx.QueryRow(`SELECT public_key FROM probe_providers WHERE id = ?`, providerID).Scan(&providerPublicKey); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: provider is not registered", ErrProbeJoinIncomplete)
	} else if err != nil {
		return fmt.Errorf("store: read probe join provider key: %w", err)
	}
	nowUnix := s.currentUnix()
	if expiresAt <= nowUnix {
		return ErrProbeExpired
	}
	if !probeTransitionAllowed(current, string(protocol.OutcomeOpenFromVantage)) {
		return ErrProbeIllegalTransition
	}
	var forwardNodeID, currentActivationID sql.NullString
	var currentForwardRevision uint64
	if err := tx.QueryRow(`SELECT node_id, current_activation_id, revision FROM forwards WHERE id = ?`, forwardID).Scan(&forwardNodeID, &currentActivationID, &currentForwardRevision); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read probe join forward: %w", err)
	}
	var operationNodeID string
	if err := tx.QueryRow(`SELECT node_id FROM probe_operations WHERE id = ?`, operationID).Scan(&operationNodeID); err != nil {
		return fmt.Errorf("store: read probe join node: %w", err)
	}
	if !forwardNodeID.Valid || forwardNodeID.String == "" || operationNodeID != forwardNodeID.String {
		return fmt.Errorf("%w: operation/forward node mismatch", ErrProbeJoinIncomplete)
	}
	if !currentActivationID.Valid || currentActivationID.String == "" || currentActivationID.String != activationID {
		return ErrCASConflict
	}
	if expectedForwardRevision == 0 || currentForwardRevision != expectedForwardRevision {
		return ErrCASConflict
	}
	var deletionIntent int
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM forward_deletion_operations WHERE forward_id = ? AND status = 'PENDING')`, forwardID).Scan(&deletionIntent); err != nil {
		return fmt.Errorf("store: read probe join deletion intent: %w", err)
	}
	if deletionIntent != 0 {
		return ErrCASConflict
	}
	var providerEnabled, independentVantage int
	if err := tx.QueryRow(`SELECT enabled, independent_vantage FROM probe_providers WHERE id = ?`, providerID).Scan(&providerEnabled, &independentVantage); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: provider is not registered", ErrProbeJoinIncomplete)
	} else if err != nil {
		return fmt.Errorf("store: read probe join provider: %w", err)
	}
	if providerEnabled == 0 || independentVantage == 0 {
		return fmt.Errorf("%w: provider is not an enabled independent vantage", ErrProbeJoinIncomplete)
	}
	var providerPayload, wan1Payload, ack1Payload, rct1Payload string
	for _, artifact := range []struct {
		kind string
		dst  *string
	}{
		{kind: "provider", dst: &providerPayload},
		{kind: "wan1", dst: &wan1Payload},
		{kind: "ack1", dst: &ack1Payload},
		{kind: "rct1", dst: &rct1Payload},
	} {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM probe_results WHERE probe_id = ? AND kind = ?`, operationID, artifact.kind).Scan(&count); err != nil {
			return fmt.Errorf("store: count probe join %s: %w", artifact.kind, err)
		}
		if count != 1 {
			return fmt.Errorf("%w: expected one %s artifact, got %d", ErrProbeJoinIncomplete, artifact.kind, count)
		}
		if err := tx.QueryRow(`SELECT payload_hex FROM probe_results WHERE probe_id = ? AND kind = ?`, operationID, artifact.kind).Scan(artifact.dst); err != nil {
			return fmt.Errorf("store: read probe join %s artifact: %w", artifact.kind, err)
		}
	}
	providerResult, err := decodeStoredProviderResult(providerPayload)
	if err != nil || !providerResult.verify(providerPublicKey) || providerResult.ProbeID != operationID ||
		!strings.EqualFold(providerResult.WAN1Frame, wan1Payload) || !strings.EqualFold(providerResult.ACK1Frame, ack1Payload) {
		return fmt.Errorf("%w: provider result is malformed, rejected, unbound, or unsigned", ErrProbeJoinIncomplete)
	}
	if providerResult.TimestampUnix < createdAt-5*60 || providerResult.TimestampUnix > expiresAt+5*60 ||
		providerResult.TimestampUnix > nowUnix+5*60 {
		return fmt.Errorf("%w: provider result timestamp outside operation window", ErrProbeJoinIncomplete)
	}
	challengeHash, err := hex.DecodeString(providerResult.ChallengeHash)
	if err != nil || len(challengeHash) != protocol.ProbeDigestLen {
		return fmt.Errorf("%w: invalid provider challenge hash", ErrProbeJoinIncomplete)
	}
	armBytes, err := hex.DecodeString(operationArmHex)
	if err != nil {
		return fmt.Errorf("%w: invalid ARM1 evidence", ErrProbeJoinIncomplete)
	}
	arm, err := protocol.ParseProbeArm(armBytes)
	if err != nil {
		return fmt.Errorf("%w: invalid ARM1 evidence: %v", ErrProbeJoinIncomplete, err)
	}
	maxExpiry := createdAt + int64((arm.TTLMS+999)/1000)
	if storedEndpoint != arm.Endpoint || storedTTLMS != arm.TTLMS ||
		!strings.EqualFold(storedExpiryOpaque, hex.EncodeToString(arm.ExpiryOpaque[:])) ||
		expiresAt > maxExpiry {
		return fmt.Errorf("%w: operation is not bound to ARM1 TTL/endpoint/opaque expiry", ErrProbeJoinIncomplete)
	}
	wan1Bytes, err := hex.DecodeString(wan1Payload)
	if err != nil {
		return fmt.Errorf("%w: invalid WAN1 evidence", ErrProbeJoinIncomplete)
	}
	frame, err := protocol.ParseProviderFrame(wan1Bytes)
	if err != nil {
		return fmt.Errorf("%w: malformed WAN1 evidence: %v", ErrProbeJoinIncomplete, err)
	}
	providerPublicKeyBytes, err := hex.DecodeString(providerPublicKey)
	if err != nil || len(providerPublicKeyBytes) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(providerPublicKeyBytes), frame.SigningBytes(), frame.Signature) {
		return fmt.Errorf("%w: WAN1 provider signature is invalid", ErrProbeJoinIncomplete)
	}
	frameChallenge := frame.ChallengeHash()
	if frame.ArmDigest != arm.Digest() || frame.ProbeID != arm.ProbeID || frame.ProviderID != arm.ProviderID ||
		frame.Activation != arm.Activation || frame.Endpoint != arm.Endpoint || frame.ExpiryOpaque != arm.ExpiryOpaque ||
		!bytes.Equal(frameChallenge[:], challengeHash) {
		return fmt.Errorf("%w: WAN1 binding mismatch", ErrProbeJoinIncomplete)
	}
	ackBytes, err := hex.DecodeString(ack1Payload)
	if err != nil {
		return fmt.Errorf("%w: invalid ACK1 evidence", ErrProbeJoinIncomplete)
	}
	ack, err := protocol.ParseProbeACK(ackBytes, nodePublicKey)
	if err != nil || ack.ArmDigest != frame.ArmDigest || ack.ChallengeHash != frameChallenge {
		return fmt.Errorf("%w: ACK1 binding mismatch", ErrProbeJoinIncomplete)
	}
	receiptBytes, err := hex.DecodeString(rct1Payload)
	if err != nil {
		return fmt.Errorf("%w: invalid RCT1 evidence", ErrProbeJoinIncomplete)
	}
	receipt, err := protocol.ParseProbeReceipt(receiptBytes, nodePublicKey)
	if err != nil || receipt.ArmDigest != frame.ArmDigest ||
		receipt.ChallengeHash != frameChallenge || receipt.ProviderID != arm.ProviderID {
		return fmt.Errorf("%w: RCT1 binding mismatch", ErrProbeJoinIncomplete)
	}
	var operationChallenge string
	if err := tx.QueryRow(`SELECT challenge_hash FROM probe_operations WHERE id = ?`, operationID).Scan(&operationChallenge); err != nil {
		return fmt.Errorf("store: read probe join challenge: %w", err)
	}
	if operationChallenge == "" || !strings.EqualFold(operationChallenge, providerResult.ChallengeHash) {
		return fmt.Errorf("%w: challenge hash mismatch", ErrProbeJoinIncomplete)
	}
	// WAN verification owns only reachability, return-path, and publication.
	// Merge those fields into the persisted mirror instead of replacing the
	// orthogonal control/listener/mapping/keepalive/target/data-plane axes.
	mergedSnapshot, err := decodeActivationSnapshot(snapshotJSON)
	if err != nil {
		return fmt.Errorf("%w: illegal activation snapshot: %v", ErrProbeJoinIncomplete, err)
	}
	var previousActivationID, previousJSON string
	if err := tx.QueryRow(`SELECT activation_id, snapshot_json FROM forward_runtime_status WHERE forward_id = ?`, forwardID).
		Scan(&previousActivationID, &previousJSON); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: runtime mirror is missing", ErrProbeJoinIncomplete)
	} else if err != nil {
		return fmt.Errorf("store: read persisted activation snapshot: %w", err)
	} else {
		previousJSON, previousGeneration, generationBound, decodeErr := decodePersistedForwardRuntimeStatus(previousJSON)
		if decodeErr != nil {
			return fmt.Errorf("%w: persisted activation snapshot is invalid", ErrProbeJoinIncomplete)
		}
		if previousActivationID != activationID || !generationBound || previousGeneration != expectedForwardRevision {
			return ErrCASConflict
		}
		previous, decodeErr := decodeActivationSnapshot(previousJSON)
		if decodeErr != nil {
			return fmt.Errorf("%w: persisted activation snapshot is invalid", ErrProbeJoinIncomplete)
		}
		mergedSnapshot.ControlState = previous.ControlState
		mergedSnapshot.ListenerState = previous.ListenerState
		mergedSnapshot.MappingState = previous.MappingState
		mergedSnapshot.KeepaliveState = previous.KeepaliveState
		mergedSnapshot.TargetHealthState = previous.TargetHealthState
		mergedSnapshot.DataPlaneState = previous.DataPlaneState
	}
	mergedJSONBytes, err := json.Marshal(mergedSnapshot)
	if err != nil {
		return fmt.Errorf("%w: marshal merged activation snapshot: %v", ErrProbeJoinIncomplete, err)
	}
	// Validate the final merged state, not only the caller-supplied WAN fields.
	// A prior mapping/listener state can make an otherwise valid probe result
	// impossible (for example FIRST_HOP_MAPPED plus verified publication).
	if err := mergedSnapshot.Validate(); err != nil {
		return fmt.Errorf("%w: merged activation snapshot is invalid: %v", ErrProbeJoinIncomplete, err)
	}
	mergedJSON := string(mergedJSONBytes)
	persistedMergedJSON, err := encodePersistedForwardRuntimeStatus(mergedJSON, expectedForwardRevision)
	if err != nil {
		return fmt.Errorf("%w: persist merged activation snapshot: %v", ErrProbeJoinIncomplete, err)
	}
	res, err := tx.Exec(`UPDATE probe_operations SET status = ?, updated_at = ?
		WHERE id = ? AND status = ? AND expires_at > ? AND expected_forward_revision = ?
		  AND EXISTS (SELECT 1 FROM forwards f WHERE f.id = ? AND f.current_activation_id = ? AND f.revision = ?
		              AND NOT EXISTS (SELECT 1 FROM forward_deletion_operations d
		                              WHERE d.forward_id = f.id AND d.status = 'PENDING'))`,
		string(protocol.OutcomeOpenFromVantage), nowUnix, operationID, expectedStatus, nowUnix,
		expectedForwardRevision, forwardID, activationID, expectedForwardRevision)
	if err != nil {
		return fmt.Errorf("store: publish probe operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: publish probe operation rows: %w", err)
	} else if n != 1 {
		return ErrProbeTerminal
	}
	statusRes, err := tx.Exec(`INSERT INTO forward_runtime_status (forward_id, activation_id, snapshot_json, updated_at)
		SELECT ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM forwards f WHERE f.id = ? AND f.current_activation_id = ? AND f.revision = ?
		              AND NOT EXISTS (SELECT 1 FROM forward_deletion_operations d
		                              WHERE d.forward_id = f.id AND d.status = 'PENDING'))
		ON CONFLICT(forward_id) DO UPDATE SET activation_id = excluded.activation_id,
		 snapshot_json = excluded.snapshot_json, updated_at = excluded.updated_at
		 WHERE excluded.activation_id = (SELECT current_activation_id FROM forwards WHERE id = excluded.forward_id)
		   AND ? = (SELECT revision FROM forwards WHERE id = excluded.forward_id)`,
		forwardID, activationID, persistedMergedJSON, nowUnix, forwardID, activationID, expectedForwardRevision, expectedForwardRevision)
	if err != nil {
		return fmt.Errorf("store: publish probe snapshot: %w", err)
	}
	if n, err := statusRes.RowsAffected(); err != nil {
		return fmt.Errorf("store: publish probe snapshot rows: %w", err)
	} else if n != 1 {
		return ErrCASConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit probe join: %w", err)
	}
	return nil
}

// ProbeOperationByArmDigest finds a live operation whose canonical ARM1 frame
// has the given digest. Expired nonterminal rows are handled by the explicit
// include-expired lookup; they must not be selected by this compatibility path.
func (s *Store) ProbeOperationByArmDigest(digest [32]byte) (ProbeOperation, error) {
	const query = `SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations INDEXED BY idx_probe_live_expiry
		WHERE status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?
		ORDER BY expires_at, id LIMIT ?`
	return s.findProbeOperationByArmDigest(digest, query, s.currentUnix(), defaultProbeLookupBudget)
}

// ProbeOperationByArmDigestForNode resolves only live operations belonging to
// nodeID. The node/status/deadline fence is part of the lookup rather than a
// caller convention, so a late frame cannot operate on another node's row.
func (s *Store) ProbeOperationByArmDigestForNode(digest [32]byte, nodeID string, nowUnix int64) (ProbeOperation, error) {
	return s.ProbeOperationByArmDigestForNodeWithLimit(digest, nodeID, nowUnix, defaultProbeLookupBudget)
}

// ProbeOperationByArmDigestForNodeWithLimit is the manager-facing lookup. Its
// limit must match the manager's durable active-operation admission bound;
// without an indexed digest column, the fallback can only prove completeness
// within that caller-supplied bounded live set.
func (s *Store) ProbeOperationByArmDigestForNodeWithLimit(digest [32]byte, nodeID string, nowUnix int64, limit int) (ProbeOperation, error) {
	const query = `SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations INDEXED BY idx_probe_live_expiry
		WHERE node_id = ? AND status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?
		ORDER BY expires_at, id LIMIT ?`
	return s.findProbeOperationByArmDigest(digest, query, nodeID, nowUnix, probeLookupLimit(limit))
}

// ProbeOperationByArmDigestForNodeIncludingExpired resolves only the bounded
// live-operation set for nodeID, including rows that crossed their deadline.
// Terminal history is not a receipt-correlation source: late frames may
// terminalize a still-live row, but they must never resurrect a terminal row.
func (s *Store) ProbeOperationByArmDigestForNodeIncludingExpired(digest [32]byte, nodeID string) (ProbeOperation, error) {
	return s.ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(digest, nodeID, defaultProbeLookupBudget)
}

// ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit is the bounded
// receipt-correlation lookup used by Manager. The limit is coupled to the
// manager's MaxActiveOperations admission setting.
func (s *Store) ProbeOperationByArmDigestForNodeIncludingExpiredWithLimit(digest [32]byte, nodeID string, limit int) (ProbeOperation, error) {
	const query = `SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations INDEXED BY idx_probe_live_expiry
		WHERE node_id = ? AND status IN ('PENDING','ARMED','IN_FLIGHT')
		ORDER BY expires_at, id LIMIT ?`
	return s.findProbeOperationByArmDigest(digest, query, nodeID, probeLookupLimit(limit))
}

// ProbeOperationByArmDigestForNodeOpenWithinReplayWithLimit finds a recently
// joined OPEN_FROM_VANTAGE operation without making terminal history a general
// receipt-correlation source. expiresAfterUnix is the lower bound for the
// operation deadline: an exact RCT1 replay is admissible only while that
// deadline remains within the protocol replay window.
func (s *Store) ProbeOperationByArmDigestForNodeOpenWithinReplayWithLimit(digest [32]byte, nodeID string, expiresAfterUnix int64, limit int) (ProbeOperation, error) {
	const query = `SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations INDEXED BY idx_probe_terminal_updated
		WHERE node_id = ?
		  AND status IN ('OPEN_FROM_VANTAGE', 'REJECTED', 'DROPPED', 'TIMEOUT', 'NO_INDEPENDENT_VANTAGE', 'PROBE_INFRA_UNAVAILABLE')
		  AND status = 'OPEN_FROM_VANTAGE' AND expires_at > ?
		ORDER BY updated_at DESC, id DESC LIMIT ?`
	return s.findProbeOperationByArmDigest(digest, query, nodeID, expiresAfterUnix, probeLookupLimit(limit))
}

func probeLookupLimit(limit int) int {
	if limit <= 0 {
		return defaultProbeLookupLimit
	}
	return limit
}

// findProbeOperationByArmDigest scans one bounded page at a time. The arm
// bytes are intentionally parsed in Go because SQLite stores the canonical
// frame as text; paging keeps the lookup bounded without silently making rows
// beyond the admitted active set unreachable.
func (s *Store) findProbeOperationByArmDigest(digest [32]byte, query string, args ...any) (ProbeOperation, error) {
	want := hex.EncodeToString(digest[:])
	if len(args) == 0 {
		return ProbeOperation{}, fmt.Errorf("store: probe lookup query has no page limit")
	}
	lookupLimit, ok := args[len(args)-1].(int)
	if !ok || lookupLimit <= 0 {
		return ProbeOperation{}, fmt.Errorf("store: probe lookup query has invalid page limit")
	}
	baseQuery := query
	baseArgs := append([]any(nil), args[:len(args)-1]...)
	byExpires := strings.Contains(baseQuery, "ORDER BY expires_at, id")
	var afterExpires, afterUpdated int64
	var afterID string
	haveCursor := false
	scanned := 0
	var corruptErr error
	var matched ProbeOperation
	matchCount := 0
	// Read one look-ahead row beyond the caller's admission budget. A full
	// page-sized result proves only that more rows may exist; the extra row
	// distinguishes an exact-boundary finite set (ErrNotFound) from a genuinely
	// truncated search (ErrProbeLookupBudget). Matches beyond lookupLimit are
	// never accepted.
	scanCeiling := lookupLimit + 1
	for scanned < scanCeiling {
		pageLimit := defaultProbeLookupLimit
		if remaining := scanCeiling - scanned; remaining < pageLimit {
			pageLimit = remaining
		}
		pageQuery := baseQuery
		pageArgs := append([]any(nil), baseArgs...)
		if haveCursor {
			if byExpires {
				pageQuery = strings.Replace(pageQuery, "ORDER BY expires_at, id LIMIT ?", "AND (expires_at > ? OR (expires_at = ? AND id > ?)) ORDER BY expires_at, id LIMIT ?", 1)
				pageArgs = append(pageArgs, afterExpires, afterExpires, afterID)
			} else {
				pageQuery = strings.Replace(pageQuery, "ORDER BY updated_at DESC, id DESC LIMIT ?", "AND (updated_at < ? OR (updated_at = ? AND id < ?)) ORDER BY updated_at DESC, id DESC LIMIT ?", 1)
				pageArgs = append(pageArgs, afterUpdated, afterUpdated, afterID)
			}
		}
		pageArgs = append(pageArgs, pageLimit)
		rows, err := s.db.Query(pageQuery, pageArgs...)
		if err != nil {
			return ProbeOperation{}, fmt.Errorf("store: scan probe operations: %w", err)
		}
		count := 0
		var lastExpires, lastUpdated int64
		var lastID string
		for rows.Next() {
			var op ProbeOperation
			if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status,
				&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
				&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
				rows.Close()
				return ProbeOperation{}, fmt.Errorf("store: scan probe operation: %w", err)
			}
			count++
			scanned++
			lastExpires, lastUpdated, lastID = op.ExpiresAt, op.UpdatedAt, op.ID
			armBytes, err := hex.DecodeString(op.ArmHex)
			if err != nil {
				if corruptErr == nil {
					corruptErr = fmt.Errorf("%w: operation %q has malformed arm_hex: %v", ErrProbeCorrupt, op.ID, err)
				}
				continue
			}
			armDigest, parseErr := ParseProbeArmLite(armBytes)
			if parseErr != nil {
				if corruptErr == nil {
					corruptErr = fmt.Errorf("%w: operation %q has invalid ARM1: %v", ErrProbeCorrupt, op.ID, parseErr)
				}
				continue
			}
			if hex.EncodeToString(armDigest[:]) == want {
				// Count a matching look-ahead row for ambiguity, but never
				// admit it as the selected operation. A duplicate exactly at
				// the budget boundary must fail closed rather than being
				// mistaken for a unique in-budget match.
				matchCount++
				if scanned <= lookupLimit {
					matched = op
				}
			}
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return ProbeOperation{}, fmt.Errorf("store: scan probe operation rows: %w", rowErr)
		}
		if count < pageLimit {
			// The query is exhausted. Corruption is terminal only when the
			// complete caller-bounded candidate set has been examined; a
			// look-ahead row is handled as budget exhaustion below. A digest
			// match is accepted only after the complete admitted set has been
			// scanned, so duplicate live rows fail closed instead of selecting
			// whichever row happens to sort first.
			if scanned <= lookupLimit {
				if matchCount > 1 {
					return ProbeOperation{}, ErrProbeAmbiguous
				}
				if matchCount == 1 && matched.ID != "" {
					return matched, nil
				}
				if corruptErr != nil {
					return ProbeOperation{}, corruptErr
				}
				return ProbeOperation{}, ErrNotFound
			}
			return ProbeOperation{}, ErrProbeLookupBudget
		}
		if scanned >= scanCeiling {
			// The look-ahead row proves that the candidate set extends beyond
			// the caller's bound. A single match is not proven unique until the
			// admitted candidate set is exhausted, so fail closed with budget
			// exhaustion rather than silently selecting it.
			if matchCount > 1 {
				return ProbeOperation{}, ErrProbeAmbiguous
			}
			return ProbeOperation{}, ErrProbeLookupBudget
		}
		haveCursor = true
		afterExpires, afterUpdated, afterID = lastExpires, lastUpdated, lastID
	}
	// The look-ahead row proves that the search was truncated. Corruption in
	// the prefix cannot be classified as terminal here because a valid target
	// may exist beyond the caller's budget; callers must retry after the bounded
	// candidate set changes.
	return ProbeOperation{}, ErrProbeLookupBudget
}

// ParseProbeArmLite computes the canonical-arm digest without full validation
// (only for digest lookup; the manager validates the full frame elsewhere).
func ParseProbeArmLite(raw []byte) ([32]byte, error) {
	arm, err := protocol.ParseProbeArm(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return arm.Digest(), nil
}

// ListProbeOperationsByStatus returns operations in the given statuses
// (bounded by TTL; used by the manager sweep).
func (s *Store) ListProbeOperationsByStatus(statuses ...string) ([]ProbeOperation, error) {
	return s.ListProbeOperationsByStatusLimit(defaultProbeLookupLimit, statuses...)
}

func (s *Store) ListProbeOperationsByStatusLimit(limit int, statuses ...string) ([]ProbeOperation, error) {
	return s.listProbeOperationsByStatusLimit(limit, nil, statuses...)
}

// ListProbeOperationsByStatusLimitAt returns only nonterminal rows whose
// expiry is after nowUnix. Recovery uses this live-first form so expired
// history cannot consume the bounded recovery page.
func (s *Store) ListProbeOperationsByStatusLimitAt(limit int, nowUnix int64, statuses ...string) ([]ProbeOperation, error) {
	return s.ListProbeOperationsByStatusLimitAtAfter(limit, nowUnix, 0, "", statuses...)
}

// ListProbeOperationsByStatusLimitAtAfter returns one fair, keyset-paged live
// recovery page. The cursor follows the indexed expiry/id order, so a small
// per-pass limit cannot permanently pin the oldest offline operation ahead of
// later live work. A caller resets the cursor after an empty or short page.
func (s *Store) ListProbeOperationsByStatusLimitAtAfter(limit int, nowUnix, afterExpires int64, afterID string, statuses ...string) ([]ProbeOperation, error) {
	if limit <= 0 {
		limit = defaultProbeLookupLimit
	}
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(statuses))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(statuses)+5)
	for _, st := range statuses {
		args = append(args, st)
	}
	args = append(args, nowUnix, afterExpires, afterExpires, afterID, limit)
	rows, err := s.db.Query(
		`SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
		        arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		   FROM probe_operations INDEXED BY idx_probe_live_expiry
		  WHERE status IN ('PENDING', 'ARMED', 'IN_FLIGHT') AND status IN (`+placeholders+`) AND expires_at > ?
		    AND (expires_at > ? OR (expires_at = ? AND id > ?))
		  ORDER BY expires_at, id LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list live probe operations page: %w", err)
	}
	defer rows.Close()
	var out []ProbeOperation
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status, &op.Endpoint,
			&op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque, &op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan live probe operation page: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func (s *Store) listProbeOperationsByStatusLimit(limit int, liveAfter *int64, statuses ...string) ([]ProbeOperation, error) {
	if limit <= 0 {
		limit = defaultProbeLookupLimit
	}
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(statuses))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(statuses)+2)
	for _, st := range statuses {
		args = append(args, st)
	}
	where := "status IN (" + placeholders + ")"
	if liveAfter != nil {
		where += " AND expires_at > ?"
		args = append(args, *liveAfter)
	}
	args = append(args, limit)
	rows, err := s.db.Query(
		`SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
		        arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		   FROM probe_operations WHERE `+where+` ORDER BY created_at, id LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list probe operations: %w", err)
	}
	defer rows.Close()
	var out []ProbeOperation
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan probe operation: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// QueueProbeOutcome durably records the terminal disposition before any
// controller outbox delivery. STALE and MISSING are terminal local decisions;
// only the current activation obtains a probe_outcome command.
func (s *Store) QueueProbeOutcome(probeID string, outcome protocol.ProbeOutcome) (string, error) {
	if probeID == "" {
		return "", ErrNotFound
	}
	// Outcome queuing reads the operation/forward/deletion state and then writes
	// both the terminal-delivery decision and, for current activations, the
	// outbox row. A deferred transaction can read a WAL snapshot that becomes
	// stale before the first write and surface SQLITE_BUSY_SNAPSHOT during
	// recovery. Reserve the writer before those reads so one caller observes a
	// deterministic serialized decision and all storage contention remains a
	// retryable error.
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("store: probe outcome conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return "", fmt.Errorf("store: begin probe outcome delivery: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	nowUnix := s.currentUnix()
	var nodeID, forwardID, activationID, status string
	var expectedForwardRevision uint64
	var operationUpdatedAt int64
	err = conn.QueryRowContext(ctx, `SELECT node_id, forward_id, activation_id, expected_forward_revision, status, updated_at FROM probe_operations WHERE id = ?`, probeID).
		Scan(&nodeID, &forwardID, &activationID, &expectedForwardRevision, &status, &operationUpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: read probe outcome operation: %w", err)
	}
	if !probeTerminal(status) {
		return "", fmt.Errorf("store: probe outcome is not terminal")
	}

	var existing string
	if err := conn.QueryRowContext(ctx, `SELECT disposition FROM probe_terminal_deliveries WHERE probe_id = ?`, probeID).Scan(&existing); err == nil {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return "", fmt.Errorf("store: commit existing probe outcome delivery: %w", err)
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read probe outcome disposition: %w", err)
	}

	disposition := "ENQUEUED"
	var currentActivation sql.NullString
	var forwardRevision uint64
	if err := conn.QueryRowContext(ctx, `SELECT current_activation_id, revision FROM forwards WHERE id = ?`, forwardID).Scan(&currentActivation, &forwardRevision); errors.Is(err, sql.ErrNoRows) {
		disposition = "MISSING"
	} else if err != nil {
		return "", fmt.Errorf("store: read probe outcome forward: %w", err)
	} else if !currentActivation.Valid || currentActivation.String != activationID ||
		expectedForwardRevision == 0 || forwardRevision != expectedForwardRevision {
		disposition = "STALE"
	} else {
		var deletionIntent int
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM forward_deletion_operations WHERE forward_id = ? AND status = 'PENDING')`, forwardID).Scan(&deletionIntent); err != nil {
			return "", fmt.Errorf("store: read probe outcome deletion intent: %w", err)
		}
		if deletionIntent != 0 {
			disposition = "STALE"
		}
	}
	if operationUpdatedAt == 0 {
		operationUpdatedAt = nowUnix
	}
	result, err := conn.ExecContext(ctx, `INSERT INTO probe_terminal_deliveries
		(probe_id, disposition, outcome, node_id, forward_id, activation_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(probe_id) DO NOTHING`, probeID, disposition, string(outcome), nodeID, forwardID, activationID, operationUpdatedAt, operationUpdatedAt)
	if err != nil {
		return "", fmt.Errorf("store: insert probe outcome disposition: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return "", fmt.Errorf("store: probe outcome disposition rows: %w", err)
	} else if affected == 0 {
		var winner string
		if err := conn.QueryRowContext(ctx, `SELECT disposition FROM probe_terminal_deliveries WHERE probe_id = ?`, probeID).Scan(&winner); err != nil {
			return "", fmt.Errorf("store: read winning probe outcome disposition: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return "", fmt.Errorf("store: commit winning probe outcome disposition: %w", err)
		}
		return winner, nil
	}
	if disposition == "ENQUEUED" {
		payload, err := json.Marshal(struct {
			ForwardID  string `json:"forward_id"`
			Activation string `json:"activation"`
			Generation uint64 `json:"generation"`
			Outcome    string `json:"outcome"`
		}{forwardID, activationID, expectedForwardRevision, string(outcome)})
		if err != nil {
			return "", fmt.Errorf("store: marshal probe outcome: %w", err)
		}
		item := ControlOutboxItem{OperationID: probeID, MessageType: "probe_outcome", NodeID: nodeID, SemanticPayload: string(payload)}
		commandID := deterministicMessageID(item.OperationID, item.MessageType)
		resultID := deterministicMessageID(commandID, "operation_complete")
		controllerResultID := deterministicMessageID(item.OperationID, "operation_complete")
		if _, err := conn.ExecContext(ctx, `INSERT INTO control_outbox
			(operation_id, message_type, node_id, semantic_payload, state, attempt_count,
			 created_at, updated_at, command_message_id, operation_complete_message_id,
			 controller_operation_complete_message_id)
			VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?, ?)`, item.OperationID, item.MessageType,
			item.NodeID, item.SemanticPayload, nowUnix, nowUnix, commandID, resultID, controllerResultID); err != nil {
			return "", fmt.Errorf("store: enqueue probe outcome: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return "", fmt.Errorf("store: commit probe outcome delivery: %w", err)
	}
	return disposition, nil
}

// ProbeOutcomeDisposition returns the durable local delivery decision.
func (s *Store) ProbeOutcomeDisposition(probeID string) (string, error) {
	var disposition string
	err := s.db.QueryRow(`SELECT disposition FROM probe_terminal_deliveries WHERE probe_id = ?`, probeID).Scan(&disposition)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: get probe outcome disposition: %w", err)
	}
	return disposition, nil
}

// ListUndeliveredTerminalProbeOperationsPage returns a caller-budgeted keyset
// page. Rows without a delivery decision and ENQUEUED rows are eligible;
// terminal local dispositions are not retried as if they were deliverable.
func (s *Store) ListUndeliveredTerminalProbeOperationsPage(limit int, afterCreated int64, afterID string) ([]ProbeOperation, error) {
	if limit <= 0 {
		limit = defaultProbeLookupLimit
	}
	rows, err := s.db.Query(`SELECT o.id, o.node_id, o.forward_id, o.activation_id, o.expected_forward_revision, o.provider_id, o.status, o.endpoint,
		o.arm_hex, o.challenge_hash, o.ttl_ms, o.expiry_opaque, o.expires_at, o.created_at, o.updated_at
		FROM probe_operations o INDEXED BY idx_probe_terminal_created
		WHERE `+probeTerminalSQL+` AND (o.created_at > ? OR (o.created_at = ? AND o.id > ?))
		  AND NOT EXISTS (SELECT 1 FROM probe_terminal_deliveries d
		                  WHERE d.probe_id = o.id AND d.disposition IN ('STALE','MISSING','EXPIRED','DELIVERED'))
		ORDER BY o.created_at, o.id LIMIT ?`, afterCreated, afterCreated, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list undelivered terminal probe operations: %w", err)
	}
	defer rows.Close()
	var out []ProbeOperation
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan undelivered terminal probe operation: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// ExpireTerminalProbeDeliveriesBeforeLimit marks offline ENQUEUED deliveries
// expired and removes their unsent outbox commands in one bounded transaction.
func (s *Store) ExpireTerminalProbeDeliveriesBeforeLimit(cutoff int64, limit int) (int, error) {
	limit = probeCleanupLimit(limit)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin terminal delivery expiry: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT d.probe_id FROM probe_terminal_deliveries d
		JOIN control_outbox o ON o.operation_id = d.probe_id AND o.message_type = 'probe_outcome'
		WHERE d.disposition = 'ENQUEUED' AND d.updated_at < ? AND o.state = 'PENDING'
		  AND NOT EXISTS (SELECT 1 FROM probe_results ack WHERE ack.probe_id = d.probe_id AND ack.kind = 'outcome_acked')
		ORDER BY d.updated_at, d.probe_id LIMIT ?`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: query terminal deliveries: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: scan terminal delivery: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("store: close terminal deliveries: %w", err)
	}
	expired := 0
	for _, id := range ids {
		res, err := tx.Exec(`UPDATE probe_terminal_deliveries SET disposition = 'EXPIRED', updated_at = ?
			WHERE probe_id = ? AND disposition = 'ENQUEUED'
			  AND EXISTS (SELECT 1 FROM control_outbox o WHERE o.operation_id = probe_terminal_deliveries.probe_id
			              AND o.message_type = 'probe_outcome' AND o.state = 'PENDING')
			  AND NOT EXISTS (SELECT 1 FROM probe_results ack WHERE ack.probe_id = probe_terminal_deliveries.probe_id
			                  AND ack.kind = 'outcome_acked')`, cutoff, id)
		if err != nil {
			return 0, fmt.Errorf("store: expire terminal delivery: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("store: expire terminal delivery rows: %w", err)
		}
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM control_outbox WHERE operation_id = ? AND message_type = 'probe_outcome' AND state = 'PENDING'`, id); err != nil {
			return 0, fmt.Errorf("store: delete expired probe outcome outbox: %w", err)
		}
		expired++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit terminal delivery expiry: %w", err)
	}
	return expired, nil
}

// ListTerminalProbeOperationsPage returns one deterministic page of terminal
// operation tombstones. Recovery uses the keyset cursor so a large audit
// backlog cannot strand a committed terminal result beyond a fixed scan cap.
func (s *Store) ListTerminalProbeOperationsPage(limit int, afterCreated int64, afterID string) ([]ProbeOperation, error) {
	if limit <= 0 {
		limit = defaultProbeLookupLimit
	}
	rows, err := s.db.Query(`SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
		arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations INDEXED BY idx_probe_terminal_created
		WHERE `+probeTerminalSQL+` AND (created_at > ? OR (created_at = ? AND id > ?))
		ORDER BY created_at, id LIMIT ?`, afterCreated, afterCreated, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list terminal probe operations: %w", err)
	}
	defer rows.Close()
	var out []ProbeOperation
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan terminal probe operation: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

const (
	probeTerminalSQL         = `status IN ('OPEN_FROM_VANTAGE','REJECTED','DROPPED','TIMEOUT','NO_INDEPENDENT_VANTAGE','PROBE_INFRA_UNAVAILABLE')`
	defaultProbeCleanupBatch = 256
	defaultProbeLookupLimit  = 256
	// Probe operations are admitted under a 1024-row active budget. Four
	// 256-row pages therefore cover the complete valid live set while making
	// unknown receipt work finite even when terminal history is unbounded.
	maxProbeLookupPages      = 4
	defaultProbeLookupBudget = maxProbeLookupPages * defaultProbeLookupLimit
)

func probeCleanupLimit(limit int) int {
	if limit <= 0 {
		return defaultProbeCleanupBatch
	}
	return limit
}

// CountLiveProbeOperations returns the number of non-terminal probe rows at
// the store's clock. The explicit At form is used by admission paths that
// already have a controlled timestamp and avoids a second wall-clock read.
func (s *Store) CountLiveProbeOperations() (int, error) {
	return s.CountLiveProbeOperationsAt(s.currentUnix())
}

func (s *Store) CountLiveProbeOperationsAt(nowUnix int64) (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM probe_operations
		WHERE status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?`, nowUnix).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count live probe operations: %w", err)
	}
	return n, nil
}

// ExpireProbeOperations advances every live operation past its deadline to a
// terminal TIMEOUT outcome. The compatibility form processes the complete
// backlog; the Limit form is used by the cancellable manager sweeper.
func (s *Store) ExpireProbeOperations(nowUnix int64) ([]ProbeOperation, error) {
	return s.ExpireProbeOperationsLimit(nowUnix, 0)
}

// ExpireProbeOperationsLimit expires at most limit rows ordered by deadline.
// A non-positive limit selects the safe default cleanup batch.
func (s *Store) ExpireProbeOperationsLimit(nowUnix int64, limit int) ([]ProbeOperation, error) {
	limit = probeCleanupLimit(limit)
	query := `SELECT id, node_id, forward_id, activation_id, expected_forward_revision, provider_id, status, endpoint,
			arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations INDEXED BY idx_probe_live_expiry
		WHERE status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at <= ?
		ORDER BY expires_at, id LIMIT ?`
	args := []any{nowUnix, limit}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query expired probe operations: %w", err)
	}
	var candidates []ProbeOperation
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ExpectedForwardRevision, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan expired probe operation: %w", err)
		}
		candidates = append(candidates, op)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: expired probe operation rows: %w", err)
	}
	rows.Close()
	if len(candidates) == 0 {
		return nil, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin probe expiry: %w", err)
	}
	defer tx.Rollback()
	expired := make([]ProbeOperation, 0, len(candidates))
	for _, op := range candidates {
		res, err := tx.Exec(`UPDATE probe_operations SET status = 'TIMEOUT', updated_at = ?
			WHERE id = ? AND status = ? AND expires_at <= ?`, nowUnix, op.ID, op.Status, nowUnix)
		if err != nil {
			return expired, fmt.Errorf("store: expire probe operation %s: %w", op.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return expired, fmt.Errorf("store: expire probe operation rows %s: %w", op.ID, err)
		}
		if n == 1 {
			op.Status = string(protocol.OutcomeTimeout)
			op.UpdatedAt = nowUnix
			expired = append(expired, op)
		}
	}
	if err := tx.Commit(); err != nil {
		return expired, fmt.Errorf("store: commit probe expiry: %w", err)
	}
	return expired, nil
}

// DeleteProbeResultsBefore removes artifacts only when their owning terminal
// tombstone is itself outside the retention window. This preserves a late or
// unacknowledged receipt attached to a recent terminal operation.
func (s *Store) DeleteProbeResultsBefore(cutoff int64) error {
	_, err := s.DeleteProbeResultsBeforeLimit(cutoff, 0)
	return err
}

// DeleteProbeResultsBeforeLimit removes at most limit result rows. A
// non-positive limit selects the safe default cleanup batch.
func (s *Store) DeleteProbeResultsBeforeLimit(cutoff int64, limit int) (int, error) {
	limit = probeCleanupLimit(limit)
	query := `DELETE FROM probe_results WHERE id IN
		(SELECT r.id FROM probe_results r JOIN probe_operations o ON o.id = r.probe_id
		 WHERE ` + probeTerminalSQL + ` AND r.kind <> 'outcome_acked' AND o.updated_at < ? ORDER BY r.id LIMIT ?)`
	args := []any{cutoff, limit}
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("store: delete old probe results: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete old probe result rows: %w", err)
	}
	return int(n), nil
}

// DeleteTerminalProbeOperationsBefore removes terminal probe tombstones after
// the retention window. Evidence is deleted first to satisfy the foreign key;
// a removed operation cannot be revived because every late write then fails
// with ErrNotFound.
func (s *Store) DeleteTerminalProbeOperationsBefore(cutoff int64) error {
	_, err := s.DeleteTerminalProbeOperationsBeforeLimit(cutoff, 0)
	return err
}

// DeleteTerminalProbeOperationsBeforeLimit removes at most limit tombstones
// in one transaction. Selecting IDs first makes the result deterministic and
// keeps the write lock bounded even when the historical backlog is large.
func (s *Store) DeleteTerminalProbeOperationsBeforeLimit(cutoff int64, limit int) (int, error) {
	limit = probeCleanupLimit(limit)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin probe tombstone gc: %w", err)
	}
	defer tx.Rollback()
	query := `SELECT id FROM probe_operations INDEXED BY idx_probe_terminal_updated WHERE ` + probeTerminalSQL + ` AND updated_at < ?
		AND (EXISTS (SELECT 1 FROM probe_results ack WHERE ack.probe_id = probe_operations.id AND ack.kind = 'outcome_acked')
		     OR EXISTS (SELECT 1 FROM probe_terminal_deliveries d WHERE d.probe_id = probe_operations.id
		              AND d.disposition IN ('EXPIRED', 'STALE', 'MISSING', 'DELIVERED')))
		ORDER BY updated_at, id LIMIT ?`
	args := []any{cutoff, limit}
	rows, err := tx.Query(query, args...)
	if err != nil {
		return 0, fmt.Errorf("store: query probe tombstones: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: scan probe tombstone: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("store: probe tombstone rows: %w", err)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM probe_results WHERE probe_id = ?`, id); err != nil {
			return 0, fmt.Errorf("store: delete probe tombstone evidence: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM probe_terminal_deliveries WHERE probe_id = ?`, id); err != nil {
			return 0, fmt.Errorf("store: delete probe terminal delivery: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM probe_operations WHERE id = ? AND `+probeTerminalSQL+` AND updated_at < ?`, id, cutoff); err != nil {
			return 0, fmt.Errorf("store: delete probe tombstone %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit probe tombstone gc: %w", err)
	}
	return len(ids), nil
}

// ProbeResult is one joined artifact of a probe operation.
type ProbeResult struct {
	ID         int64
	ProbeID    string
	Kind       string // provider|wan1|ack1|rct1
	PayloadHex string
	CreatedAt  int64
}

// RecordProbeResult appends one probe result artifact. A probe may have at
// most one artifact of each kind; the immediate transaction makes that
// invariant hold even when provider and receipt work race.
func (s *Store) RecordProbeResult(probeID, kind, payloadHex string) error {
	switch kind {
	case "provider", "wan1", "ack1", "rct1":
	default:
		return fmt.Errorf("store: unknown probe result kind %q", kind)
	}
	if probeID == "" || payloadHex == "" {
		return errors.New("store: empty probe result")
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("store: probe result conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin probe result: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var status string
	var expiresAt int64
	if err := conn.QueryRowContext(context.Background(),
		`SELECT status, expires_at FROM probe_operations WHERE id = ?`, probeID,
	).Scan(&status, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read probe result operation: %w", err)
	}
	// Check exact evidence before lifecycle admission. A concurrent join may
	// have published the operation after another caller durably inserted this
	// same artifact; accepting that exact replay is idempotent and does not
	// reopen or rewrite a terminal operation. Conflicting evidence remains a
	// fail-closed error.
	var existingPayload string
	if err := conn.QueryRowContext(context.Background(),
		`SELECT payload_hex FROM probe_results WHERE probe_id = ? AND kind = ?`, probeID, kind,
	).Scan(&existingPayload); err == nil {
		if existingPayload == payloadHex {
			if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
				return fmt.Errorf("store: commit duplicate probe result: %w", err)
			}
			committed = true
			return nil
		}
		return fmt.Errorf("%w: %s", ErrProbeDuplicateEvidence, kind)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: check duplicate probe result: %w", err)
	}
	if probeTerminal(status) {
		return ErrProbeTerminal
	}
	if expiresAt <= s.currentUnix() {
		return ErrProbeExpired
	}
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO probe_results (probe_id, kind, payload_hex, created_at) VALUES (?, ?, ?, ?)`,
		probeID, kind, payloadHex, s.currentUnix()); err != nil {
		return fmt.Errorf("store: record probe result: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return fmt.Errorf("store: commit probe result: %w", err)
	}
	committed = true
	return nil
}

// ListProbeResults returns the joined artifacts for a probe in id order.
func (s *Store) ListProbeResults(probeID string) ([]ProbeResult, error) {
	rows, err := s.db.Query(
		`SELECT id, probe_id, kind, payload_hex, created_at
		   FROM probe_results WHERE probe_id = ? ORDER BY id`, probeID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list probe results: %w", err)
	}
	defer rows.Close()
	var out []ProbeResult
	for rows.Next() {
		var r ProbeResult
		if err := rows.Scan(&r.ID, &r.ProbeID, &r.Kind, &r.PayloadHex, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan probe result: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Controller-side orthogonal activation mirror (frozen P06 core schema:
// forward_activations + forward_runtime_status, docs/state-model.md §1).
// The mirror is a display/API surface; the agent's AppliedForwardState is the
// durable LKG and the agent-side state machine owns the CAS semantics. The
// mirror refuses stale events: an update for an activation that is neither
// the mirror's current activation nor the forward's current activation is
// rejected (ErrCASConflict), so an old event can never overwrite the current
// activation's snapshot.
// ---------------------------------------------------------------------------

// ForwardActivationRow is the frozen forward_activations row (P06 0001).
type ForwardActivationRow struct {
	ID           string
	ForwardID    string
	ActivationID string
	SpecRevision uint64
	CreatedAt    int64
}

// EnsureForwardActivation inserts the activation record if absent (frozen
// UNIQUE(forward_id, activation_id)); an existing row is untouched.
func (s *Store) EnsureForwardActivation(a ForwardActivationRow) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO forward_activations
		    (id, forward_id, activation_id, spec_revision, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.ForwardID, a.ActivationID, a.SpecRevision, now(),
	)
	if err != nil {
		return fmt.Errorf("store: ensure forward activation: %w", err)
	}
	return nil
}

// ForwardRuntimeStatus is the frozen forward_runtime_status row (P06 0001):
// the current orthogonal snapshot per forward, bound to one activation.
type ForwardRuntimeStatus struct {
	ForwardID    string
	ActivationID string
	SnapshotJSON string
	UpdatedAt    int64
	// Generation is the exact forwards.revision observed by the Agent when
	// this mirror was written. GenerationBound is false for legacy rows that
	// predate the durable generation envelope; callers must fail closed rather
	// than treating such a row as current evidence.
	Generation      uint64
	GenerationBound bool
}

// persistedForwardRuntimeStatus is an internal envelope for the existing
// snapshot_json column. Keeping the generation beside the snapshot avoids a
// schema rewrite while making same-activation revision advances durable across
// restart. GetForwardRuntimeStatus unwraps it so API callers continue to see
// the frozen ActivationStates JSON rather than storage metadata.
type persistedForwardRuntimeStatus struct {
	Generation uint64          `json:"generation"`
	Snapshot   json.RawMessage `json:"snapshot"`
}

func encodePersistedForwardRuntimeStatus(snapshotJSON string, generation uint64) (string, error) {
	if _, err := decodeActivationSnapshot(snapshotJSON); err != nil {
		return "", err
	}
	envelope, err := json.Marshal(persistedForwardRuntimeStatus{
		Generation: generation,
		Snapshot:   json.RawMessage([]byte(snapshotJSON)),
	})
	if err != nil {
		return "", fmt.Errorf("marshal runtime status envelope: %w", err)
	}
	return string(envelope), nil
}

func decodePersistedForwardRuntimeStatus(raw string) (snapshotJSON string, generation uint64, bound bool, err error) {
	var fields map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal([]byte(raw), &fields); unmarshalErr == nil {
		if snapshotRaw, ok := fields["snapshot"]; ok {
			generationRaw, generationOK := fields["generation"]
			if !generationOK {
				return "", 0, false, errors.New("runtime status envelope has no generation")
			}
			if err := json.Unmarshal(generationRaw, &generation); err != nil {
				return "", 0, false, fmt.Errorf("runtime status envelope generation: %w", err)
			}
			if _, err := decodeActivationSnapshot(string(snapshotRaw)); err != nil {
				return "", 0, false, fmt.Errorf("runtime status envelope snapshot: %w", err)
			}
			return string(snapshotRaw), generation, true, nil
		}
	}
	if _, err := decodeActivationSnapshot(raw); err != nil {
		return "", 0, false, err
	}
	// Rows written before the generation envelope are readable for display and
	// stale-state comparisons, but are never admissible for Arm or publication.
	return raw, 0, false, nil
}

// SetForwardRuntimeStatus upserts the orthogonal snapshot only when the event
// names both forwards.current_activation_id and the exact forward revision.
// Before a current activation exists, the one recorded forward_activations row
// may initialize/update its mirror at that same revision. Both predicates are
// part of the write statement, so an existing same-activation row cannot
// create a TOCTOU bypass after any forward revision advances the generation.
func (s *Store) SetForwardRuntimeStatus(forwardID, activationID string, expectedForwardRevision uint64, snapshotJSON string) error {
	persistedSnapshotJSON, err := encodePersistedForwardRuntimeStatus(snapshotJSON, expectedForwardRevision)
	if err != nil {
		return fmt.Errorf("store: invalid forward runtime snapshot: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT INTO forward_runtime_status (forward_id, activation_id, snapshot_json, updated_at)
		 SELECT ?, ?, ?, ?
		  WHERE EXISTS (
		        SELECT 1 FROM forwards f
		         WHERE f.id = ? AND f.revision = ? AND (
		               f.current_activation_id = ?
		               OR (COALESCE(f.current_activation_id, '') = '' AND EXISTS (
		                     SELECT 1 FROM forward_activations a
		                      WHERE a.forward_id = f.id AND a.activation_id = ?
		               ))
		         )
		  )
		 ON CONFLICT(forward_id) DO UPDATE SET
		    activation_id = excluded.activation_id,
		    snapshot_json = excluded.snapshot_json,
		    updated_at = excluded.updated_at
		  WHERE EXISTS (
		        SELECT 1 FROM forwards f
		         WHERE f.id = excluded.forward_id AND f.revision = ? AND (
		               f.current_activation_id = excluded.activation_id
		               OR (COALESCE(f.current_activation_id, '') = ''
		                   AND forward_runtime_status.activation_id = excluded.activation_id)
		         )
		  )`,
		forwardID, activationID, persistedSnapshotJSON, now(), forwardID, expectedForwardRevision,
		activationID, activationID, expectedForwardRevision,
	)
	if err != nil {
		return fmt.Errorf("store: set forward runtime status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set forward runtime status rows: %w", err)
	} else if n == 0 {
		var exists int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM forwards WHERE id = ?`, forwardID).Scan(&exists); err != nil {
			return fmt.Errorf("store: classify forward runtime status conflict: %w", err)
		}
		if exists == 0 {
			return ErrNotFound
		}
		return ErrCASConflict
	}
	return nil
}

// GetForwardRuntimeStatus returns the mirror row for a forward.
func (s *Store) GetForwardRuntimeStatus(forwardID string) (ForwardRuntimeStatus, error) {
	var r ForwardRuntimeStatus
	var persistedSnapshotJSON string
	err := s.db.QueryRow(
		`SELECT forward_id, activation_id, snapshot_json, updated_at
		   FROM forward_runtime_status WHERE forward_id = ?`, forwardID,
	).Scan(&r.ForwardID, &r.ActivationID, &persistedSnapshotJSON, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwardRuntimeStatus{}, ErrNotFound
	}
	if err != nil {
		return ForwardRuntimeStatus{}, fmt.Errorf("store: get forward runtime status: %w", err)
	}
	r.SnapshotJSON, r.Generation, r.GenerationBound, err = decodePersistedForwardRuntimeStatus(persistedSnapshotJSON)
	if err != nil {
		return ForwardRuntimeStatus{}, fmt.Errorf("store: decode forward runtime status: %w", err)
	}
	return r, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
