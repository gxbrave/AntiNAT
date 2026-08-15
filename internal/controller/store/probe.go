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
	ID            string
	NodeID        string
	ForwardID     string
	ActivationID  string
	ProviderID    string
	Status        string
	Endpoint      string
	ArmHex        string
	ChallengeHash string
	TTLMS         uint64
	ExpiryOpaque  string
	ExpiresAt     int64
	CreatedAt     int64
	UpdatedAt     int64
}

// CreateProbeOperation inserts a PENDING operation row.
func (s *Store) CreateProbeOperation(op ProbeOperation) (ProbeOperation, error) {
	ts := s.currentUnix()
	_, err := s.db.Exec(
		`INSERT INTO probe_operations
		    (id, node_id, forward_id, activation_id, provider_id, status, endpoint,
		     arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, op.ForwardID, op.ActivationID, op.ProviderID, orDefault(op.Status, "PENDING"),
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
	tx, err := s.db.Begin()
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: begin probe bundle: %w", err)
	}
	defer tx.Rollback()
	ts := s.currentUnix()
	// Bind the durable arm to the forward's current activation at the same
	// transaction boundary as the operation/outbox insert. The Manager checks
	// this before provider selection as a fast path, but this CAS is the actual
	// race fence when an activation changes between those two steps.
	var forwardNodeID, currentActivationID sql.NullString
	if err := tx.QueryRow(`SELECT node_id, current_activation_id FROM forwards WHERE id = ?`, op.ForwardID).
		Scan(&forwardNodeID, &currentActivationID); errors.Is(err, sql.ErrNoRows) {
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
	if _, err := tx.Exec(`INSERT INTO probe_operations
		(id, node_id, forward_id, activation_id, provider_id, status, endpoint,
		 arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.NodeID, op.ForwardID, op.ActivationID, op.ProviderID, orDefault(op.Status, "PENDING"),
		op.Endpoint, op.ArmHex, op.ChallengeHash, op.TTLMS, op.ExpiryOpaque, op.ExpiresAt, ts, ts); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: probe bundle operation: %w", err)
	}
	if err := insertOutboxTx(tx, outbox); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: probe bundle outbox: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProbeOperation{}, fmt.Errorf("store: commit probe bundle: %w", err)
	}
	return s.GetProbeOperation(op.ID)
}

// GetProbeOperation returns an operation row by probe id.
func (s *Store) GetProbeOperation(id string) (ProbeOperation, error) {
	var op ProbeOperation
	err := s.db.QueryRow(
		`SELECT id, node_id, forward_id, activation_id, provider_id, status, endpoint,
		        arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		   FROM probe_operations WHERE id = ?`, id,
	).Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ProviderID, &op.Status,
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
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin probe status: %w", err)
	}
	defer tx.Rollback()
	var current string
	var expiresAt int64
	if err := tx.QueryRow(`SELECT status, expires_at FROM probe_operations WHERE id = ?`, id).Scan(&current, &expiresAt); errors.Is(err, sql.ErrNoRows) {
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
	res, err := tx.Exec(`UPDATE probe_operations SET status = ?, updated_at = ?
		WHERE id = ? AND status = ?`, status, nowUnix, id, current)
	if err != nil {
		return fmt.Errorf("store: set probe operation status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe operation status rows: %w", err)
	} else if n != 1 {
		return ErrCASConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit probe status: %w", err)
	}
	return nil
}

// SetProbeOperationChallenge records the joined challenge hash while the
// operation is still live. A terminal/expired row cannot be rewritten by a
// late provider response.
func (s *Store) SetProbeOperationChallenge(id, challengeHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin probe challenge: %w", err)
	}
	defer tx.Rollback()
	ts := s.currentUnix()
	var status, existing string
	var expiresAt int64
	if err := tx.QueryRow(`SELECT status, challenge_hash, expires_at FROM probe_operations WHERE id = ?`, id).
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
	if challengeHash == "" {
		return fmt.Errorf("%w: challenge hash must be non-empty hexadecimal text", ErrProbeJoinIncomplete)
	}
	for _, r := range challengeHash {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return fmt.Errorf("%w: challenge hash must be non-empty hexadecimal text", ErrProbeJoinIncomplete)
		}
	}
	// Store one canonical representation so later comparisons cannot be
	// bypassed by casing. The final join boundary additionally requires the
	// provider challenge hash to decode to the protocol's 32-byte digest.
	challengeHash = strings.ToLower(challengeHash)
	res, err := tx.Exec(`UPDATE probe_operations SET challenge_hash = ?, updated_at = ?
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
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit probe challenge: %w", err)
	}
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
	if err := protocol.ValidateStrictJSON([]byte(snapshotJSON), activationSnapshotJSONSchema); err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal([]byte(snapshotJSON), &snapshot); err != nil {
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
	if err := protocol.ValidateStrictJSON([]byte(payload), storedProviderResultJSONSchema); err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
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
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin probe join: %w", err)
	}
	defer tx.Rollback()
	var current, storedForwardID, storedActivationID, providerID, providerPublicKey, storedEndpoint, storedExpiryOpaque, operationArmHex string
	var expiresAt, createdAt int64
	var storedTTLMS uint64
	if err := tx.QueryRow(`SELECT status, forward_id, activation_id, expires_at, created_at, provider_id,
		endpoint, ttl_ms, expiry_opaque, arm_hex
		FROM probe_operations WHERE id = ?`, operationID).Scan(&current, &storedForwardID, &storedActivationID, &expiresAt, &createdAt, &providerID,
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
	if err := tx.QueryRow(`SELECT node_id, current_activation_id FROM forwards WHERE id = ?`, forwardID).Scan(&forwardNodeID, &currentActivationID); errors.Is(err, sql.ErrNoRows) {
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
	res, err := tx.Exec(`UPDATE probe_operations SET status = ?, updated_at = ?
		WHERE id = ? AND status = ? AND expires_at > ?`, string(protocol.OutcomeOpenFromVantage), nowUnix, operationID, expectedStatus, nowUnix)
	if err != nil {
		return fmt.Errorf("store: publish probe operation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: publish probe operation rows: %w", err)
	} else if n != 1 {
		return ErrProbeTerminal
	}
	statusRes, err := tx.Exec(`INSERT INTO forward_runtime_status (forward_id, activation_id, snapshot_json, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(forward_id) DO UPDATE SET activation_id = excluded.activation_id,
		 snapshot_json = excluded.snapshot_json, updated_at = excluded.updated_at
		 WHERE forward_runtime_status.activation_id = excluded.activation_id
		 OR excluded.activation_id = (SELECT current_activation_id FROM forwards WHERE id = excluded.forward_id)`, forwardID, activationID, snapshotJSON, nowUnix)
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

// ProbeOperationByArmDigest finds the operation whose canonical ARM1 frame
// has the given digest. The digest uniquely identifies the arm; the scan is
// bounded by the operation TTL (probe state is bounded and expirable).
func (s *Store) ProbeOperationByArmDigest(digest [32]byte) (ProbeOperation, error) {
	rows, err := s.db.Query(`SELECT id, node_id, forward_id, activation_id, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations ORDER BY expires_at, id LIMIT ?`, defaultProbeLookupLimit)
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: scan probe operations: %w", err)
	}
	defer rows.Close()
	want := hex.EncodeToString(digest[:])
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return ProbeOperation{}, fmt.Errorf("store: scan probe operation: %w", err)
		}
		armBytes, err := hex.DecodeString(op.ArmHex)
		if err != nil {
			continue
		}
		arm, err := ParseProbeArmLite(armBytes)
		if err != nil {
			continue
		}
		if hex.EncodeToString(arm[:]) == want {
			return op, nil
		}
	}
	return ProbeOperation{}, ErrNotFound
}

// ProbeOperationByArmDigestForNode resolves only live operations belonging to
// nodeID. The node/status/deadline fence is part of the lookup rather than a
// caller convention, so a late frame cannot operate on another node's row.
func (s *Store) ProbeOperationByArmDigestForNode(digest [32]byte, nodeID string, nowUnix int64) (ProbeOperation, error) {
	rows, err := s.db.Query(`SELECT id, node_id, forward_id, activation_id, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations
		WHERE node_id = ? AND status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?
		ORDER BY expires_at, id LIMIT ?`, nodeID, nowUnix, defaultProbeLookupLimit)
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: scan live probe operations: %w", err)
	}
	defer rows.Close()
	want := hex.EncodeToString(digest[:])
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return ProbeOperation{}, fmt.Errorf("store: scan live probe operation: %w", err)
		}
		armBytes, err := hex.DecodeString(op.ArmHex)
		if err != nil {
			continue
		}
		arm, err := ParseProbeArmLite(armBytes)
		if err == nil && hex.EncodeToString(arm[:]) == want {
			return op, nil
		}
	}
	return ProbeOperation{}, ErrNotFound
}

// ProbeOperationByArmDigestForNodeIncludingExpired resolves an operation for
// nodeID without applying status or deadline predicates. The caller uses the
// returned row to terminalize a receipt that crossed the deadline, or to ignore
// evidence that arrived after the sweeper already wrote a terminal tombstone.
func (s *Store) ProbeOperationByArmDigestForNodeIncludingExpired(digest [32]byte, nodeID string) (ProbeOperation, error) {
	rows, err := s.db.Query(`SELECT id, node_id, forward_id, activation_id, provider_id, status,
		endpoint, arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations
		WHERE node_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?`, nodeID, defaultProbeLookupLimit)
	if err != nil {
		return ProbeOperation{}, fmt.Errorf("store: scan probe operations: %w", err)
	}
	defer rows.Close()
	want := hex.EncodeToString(digest[:])
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return ProbeOperation{}, fmt.Errorf("store: scan probe operation: %w", err)
		}
		armBytes, err := hex.DecodeString(op.ArmHex)
		if err != nil {
			continue
		}
		arm, err := ParseProbeArmLite(armBytes)
		if err == nil && hex.EncodeToString(arm[:]) == want {
			return op, nil
		}
	}
	return ProbeOperation{}, ErrNotFound
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
	if limit <= 0 {
		limit = defaultProbeLookupLimit
	}
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(statuses))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(statuses))
	for _, st := range statuses {
		args = append(args, st)
	}
	args = append(args, limit)
	rows, err := s.db.Query(
		`SELECT id, node_id, forward_id, activation_id, provider_id, status, endpoint,
		        arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		   FROM probe_operations WHERE status IN (`+placeholders+`) ORDER BY created_at LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list probe operations: %w", err)
	}
	defer rows.Close()
	var out []ProbeOperation
	for rows.Next() {
		var op ProbeOperation
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ProviderID, &op.Status,
			&op.Endpoint, &op.ArmHex, &op.ChallengeHash, &op.TTLMS, &op.ExpiryOpaque,
			&op.ExpiresAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan probe operation: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

const (
	probeTerminalSQL         = `status IN ('OPEN_FROM_VANTAGE','REJECTED','DROPPED','TIMEOUT','NO_INDEPENDENT_VANTAGE','PROBE_INFRA_UNAVAILABLE')`
	defaultProbeCleanupBatch = 256
	defaultProbeLookupLimit  = 256
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
	query := `SELECT id, node_id, forward_id, activation_id, provider_id, status, endpoint,
			arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		FROM probe_operations
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
		if err := rows.Scan(&op.ID, &op.NodeID, &op.ForwardID, &op.ActivationID, &op.ProviderID, &op.Status,
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
		 WHERE ` + probeTerminalSQL + ` AND o.updated_at < ? ORDER BY r.id LIMIT ?)`
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
	query := `SELECT id FROM probe_operations WHERE ` + probeTerminalSQL + ` AND updated_at < ? ORDER BY updated_at, id LIMIT ?`
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
	if probeTerminal(status) {
		return ErrProbeTerminal
	}
	if expiresAt <= s.currentUnix() {
		return ErrProbeExpired
	}
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
}

// SetForwardRuntimeStatus upserts the orthogonal snapshot under an
// activation CAS. The write is accepted only when the mirror row is absent,
// already bound to the same activation, or the event's activation is the
// forward's CURRENT activation (the replacement path when the activation
// advances). Any other write — a stale event from an older activation — is
// rejected with ErrCASConflict and leaves the row untouched.
func (s *Store) SetForwardRuntimeStatus(forwardID, activationID, snapshotJSON string) error {
	if _, err := decodeActivationSnapshot(snapshotJSON); err != nil {
		return fmt.Errorf("store: invalid forward runtime snapshot: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT INTO forward_runtime_status (forward_id, activation_id, snapshot_json, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(forward_id) DO UPDATE SET
		    activation_id = excluded.activation_id,
		    snapshot_json = excluded.snapshot_json,
		    updated_at = excluded.updated_at
		  WHERE forward_runtime_status.activation_id = excluded.activation_id
		     OR excluded.activation_id = (SELECT current_activation_id FROM forwards WHERE id = excluded.forward_id)`,
		forwardID, activationID, snapshotJSON, now(),
	)
	if err != nil {
		return fmt.Errorf("store: set forward runtime status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set forward runtime status rows: %w", err)
	} else if n == 0 {
		return ErrCASConflict
	}
	return nil
}

// GetForwardRuntimeStatus returns the mirror row for a forward.
func (s *Store) GetForwardRuntimeStatus(forwardID string) (ForwardRuntimeStatus, error) {
	var r ForwardRuntimeStatus
	err := s.db.QueryRow(
		`SELECT forward_id, activation_id, snapshot_json, updated_at
		   FROM forward_runtime_status WHERE forward_id = ?`, forwardID,
	).Scan(&r.ForwardID, &r.ActivationID, &r.SnapshotJSON, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ForwardRuntimeStatus{}, ErrNotFound
	}
	if err != nil {
		return ForwardRuntimeStatus{}, fmt.Errorf("store: get forward runtime status: %w", err)
	}
	return r, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
