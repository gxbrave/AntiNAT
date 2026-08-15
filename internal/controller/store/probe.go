// P10-owned store extension: the durable probe provider registry, probe
// operation journal, and the controller-side orthogonal activation mirror
// (migration 0004, frozen docs/protocol.md §7/§8 and docs/state-model.md §1).
// The probe manager consumes these rows; the hub remains transport-only.
package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	ts := now()
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
	ts := now()
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
		return ErrProbeTerminal
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
	if expiresAt <= now() && status != string(protocol.OutcomeTimeout) {
		return ErrProbeExpired
	}
	if _, err := tx.Exec(`UPDATE probe_operations SET status = ?, updated_at = ? WHERE id = ?`, status, now(), id); err != nil {
		return fmt.Errorf("store: set probe operation status: %w", err)
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
	ts := now()
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

// PublishProbeJoin atomically transitions the operation to OPEN_FROM_VANTAGE
// and persists its legal activation mirror. Observers can never see an OPEN
// operation without its corresponding frozen snapshot.
func (s *Store) PublishProbeJoin(operationID, expectedStatus, forwardID, activationID, snapshotJSON string) error {
	var snapshot protocol.ActivationStates
	dec := json.NewDecoder(strings.NewReader(snapshotJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: malformed activation snapshot: %v", ErrProbeJoinIncomplete, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: malformed activation snapshot trailing data", ErrProbeJoinIncomplete)
	}
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("%w: illegal activation snapshot: %v", ErrProbeJoinIncomplete, err)
	}
	if expectedStatus != "IN_FLIGHT" {
		return fmt.Errorf("%w: expected status must be IN_FLIGHT", ErrProbeIllegalTransition)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin probe join: %w", err)
	}
	defer tx.Rollback()
	var current, storedForwardID, storedActivationID, providerID string
	var expiresAt int64
	if err := tx.QueryRow(`SELECT status, forward_id, activation_id, expires_at, provider_id
		FROM probe_operations WHERE id = ?`, operationID).Scan(&current, &storedForwardID, &storedActivationID, &expiresAt, &providerID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read probe join status: %w", err)
	}
	if current != expectedStatus {
		return ErrProbeTerminal
	}
	if storedForwardID != forwardID || storedActivationID != activationID {
		return fmt.Errorf("%w: operation binding mismatch", ErrProbeJoinIncomplete)
	}
	nowUnix := now()
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
	if currentActivationID.Valid && currentActivationID.String != "" && currentActivationID.String != activationID {
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
	var providerPayload, wan1Payload, ack1Payload string
	for _, artifact := range []struct {
		kind string
		dst  *string
	}{
		{kind: "provider", dst: &providerPayload},
		{kind: "wan1", dst: &wan1Payload},
		{kind: "ack1", dst: &ack1Payload},
		{kind: "rct1", dst: new(string)},
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
	var providerResult struct {
		ProbeID       string `json:"probe_id"`
		Accepted      bool   `json:"accepted"`
		ChallengeHash string `json:"challenge_hash"`
		WAN1Frame     string `json:"wan1_frame"`
		ACK1Frame     string `json:"ack1_frame"`
	}
	if err := json.Unmarshal([]byte(providerPayload), &providerResult); err != nil ||
		!providerResult.Accepted || providerResult.ProbeID != operationID || providerResult.ChallengeHash == "" ||
		providerResult.WAN1Frame == "" || providerResult.ACK1Frame == "" ||
		!strings.EqualFold(providerResult.WAN1Frame, wan1Payload) || !strings.EqualFold(providerResult.ACK1Frame, ack1Payload) {
		return fmt.Errorf("%w: provider result is malformed, rejected, or unbound", ErrProbeJoinIncomplete)
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
		FROM probe_operations`)
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
		WHERE node_id = ? AND status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?`, nodeID, nowUnix)
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
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(statuses))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(statuses))
	for _, st := range statuses {
		args = append(args, st)
	}
	rows, err := s.db.Query(
		`SELECT id, node_id, forward_id, activation_id, provider_id, status, endpoint,
		        arm_hex, challenge_hash, ttl_ms, expiry_opaque, expires_at, created_at, updated_at
		   FROM probe_operations WHERE status IN (`+placeholders+`) ORDER BY created_at`,
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

// CountLiveProbeOperations returns the number of non-terminal probe rows.
func (s *Store) CountLiveProbeOperations() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM probe_operations
		WHERE status IN ('PENDING','ARMED','IN_FLIGHT') AND expires_at > ?`, now()).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count live probe operations: %w", err)
	}
	return n, nil
}

// ExpireProbeOperations advances every live operation past its deadline to a
// terminal TIMEOUT outcome. It is intentionally idempotent and returns the
// rows that were observed expired for audit/sweeper metrics.
func (s *Store) ExpireProbeOperations(nowUnix int64) ([]ProbeOperation, error) {
	ops, err := s.ListProbeOperationsByStatus("PENDING", "ARMED", "IN_FLIGHT")
	if err != nil {
		return nil, err
	}
	var expired []ProbeOperation
	for _, op := range ops {
		if op.ExpiresAt > nowUnix {
			continue
		}
		if err := s.SetProbeOperationStatusCAS(op.ID, op.Status, string(protocol.OutcomeTimeout)); err != nil {
			if errors.Is(err, ErrProbeTerminal) || errors.Is(err, ErrNotFound) {
				continue
			}
			return expired, err
		}
		op.Status = string(protocol.OutcomeTimeout)
		expired = append(expired, op)
	}
	return expired, nil
}

// DeleteProbeResultsBefore bounds the durable artifact journal after the
// operation retention window. It never removes a live operation's artifacts.
func (s *Store) DeleteProbeResultsBefore(cutoff int64) error {
	_, err := s.db.Exec(`DELETE FROM probe_results WHERE created_at < ? AND probe_id IN
		(SELECT id FROM probe_operations WHERE status IN ('OPEN_FROM_VANTAGE','REJECTED','DROPPED','TIMEOUT','NO_INDEPENDENT_VANTAGE','PROBE_INFRA_UNAVAILABLE'))`, cutoff)
	if err != nil {
		return fmt.Errorf("store: delete old probe results: %w", err)
	}
	return nil
}

// DeleteTerminalProbeOperationsBefore removes terminal probe tombstones after
// the retention window. Evidence is deleted first to satisfy the foreign key;
// a removed operation cannot be revived because every late write then fails
// with ErrNotFound.
func (s *Store) DeleteTerminalProbeOperationsBefore(cutoff int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin probe tombstone gc: %w", err)
	}
	defer tx.Rollback()
	const terminal = `status IN ('OPEN_FROM_VANTAGE','REJECTED','DROPPED','TIMEOUT','NO_INDEPENDENT_VANTAGE','PROBE_INFRA_UNAVAILABLE')`
	if _, err := tx.Exec(`DELETE FROM probe_results WHERE probe_id IN
		(SELECT id FROM probe_operations WHERE `+terminal+` AND updated_at < ?)`, cutoff); err != nil {
		return fmt.Errorf("store: delete probe tombstone evidence: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM probe_operations WHERE `+terminal+` AND updated_at < ?`, cutoff); err != nil {
		return fmt.Errorf("store: delete probe tombstones: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit probe tombstone gc: %w", err)
	}
	return nil
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
	if expiresAt <= now() {
		return ErrProbeExpired
	}
	var existing int
	if err := conn.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM probe_results WHERE probe_id = ? AND kind = ?`, probeID, kind,
	).Scan(&existing); err != nil {
		return fmt.Errorf("store: check duplicate probe result: %w", err)
	}
	if existing != 0 {
		return fmt.Errorf("%w: %s", ErrProbeDuplicateEvidence, kind)
	}
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO probe_results (probe_id, kind, payload_hex, created_at) VALUES (?, ?, ?, ?)`,
		probeID, kind, payloadHex, now()); err != nil {
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
