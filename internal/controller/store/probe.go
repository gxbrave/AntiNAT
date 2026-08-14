// P10-owned store extension: the durable probe provider registry, probe
// operation journal, and the controller-side orthogonal activation mirror
// (migration 0004, frozen docs/protocol.md §7/§8 and docs/state-model.md §1).
// The probe manager consumes these rows; the hub remains transport-only.
package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// ProbeProvider is a registered operator-owned probe vantage service. The
// public key verifies signed provider results; the egress IP is the exact
// source the ARM1 frame pins as expected_source_ip.
type ProbeProvider struct {
	ID        string
	Name      string
	PublicKey string
	EgressIP  string
	Endpoint  string
	Enabled   bool
	CreatedAt int64
	UpdatedAt int64
}

// CreateProbeProvider registers a provider. The id is unique.
func (s *Store) CreateProbeProvider(p ProbeProvider) (ProbeProvider, error) {
	ts := now()
	_, err := s.db.Exec(
		`INSERT INTO probe_providers (id, name, public_key, egress_ip, endpoint, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.PublicKey, p.EgressIP, p.Endpoint, boolInt(p.Enabled), ts, ts,
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
		`SELECT id, name, public_key, egress_ip, endpoint, enabled, created_at, updated_at
		   FROM probe_providers WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.PublicKey, &p.EgressIP, &p.Endpoint, &enabled, &p.CreatedAt, &p.UpdatedAt)
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

// ListProbeProviders returns every registered provider.
func (s *Store) ListProbeProviders() ([]ProbeProvider, error) {
	rows, err := s.db.Query(
		`SELECT id, name, public_key, egress_ip, endpoint, enabled, created_at, updated_at
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
		if err := rows.Scan(&p.ID, &p.Name, &p.PublicKey, &p.EgressIP, &p.Endpoint, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
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

// SetProbeOperationStatus advances an operation's status.
func (s *Store) SetProbeOperationStatus(id, status string) error {
	res, err := s.db.Exec(
		`UPDATE probe_operations SET status = ?, updated_at = ? WHERE id = ?`,
		status, now(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set probe operation status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe operation rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// SetProbeOperationChallenge records the joined challenge hash.
func (s *Store) SetProbeOperationChallenge(id, challengeHash string) error {
	res, err := s.db.Exec(
		`UPDATE probe_operations SET challenge_hash = ?, updated_at = ? WHERE id = ?`,
		challengeHash, now(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set probe operation challenge: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: set probe operation challenge rows: %w", err)
	} else if n != 1 {
		return ErrNotFound
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

// RecordProbeResult appends a probe result artifact.
func (s *Store) RecordProbeResult(probeID, kind, payloadHex string) error {
	_, err := s.db.Exec(
		`INSERT INTO probe_results (probe_id, kind, payload_hex, created_at) VALUES (?, ?, ?, ?)`,
		probeID, kind, payloadHex, now(),
	)
	if err != nil {
		return fmt.Errorf("store: record probe result: %w", err)
	}
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
