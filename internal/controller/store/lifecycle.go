// P14 Story 3/4/5 controller-side lifecycle rows: node cleanup tombstones
// (force delete keeps the old Agent key out), key rotation operation journals
// (PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED) and restore
// reconciliation records. All three are durable phase-journal rows under the
// 0008_lifecycle.sql tables (v0.8 §6-part: persist intent BEFORE any external
// side effect).
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// NodeCleanupTombstone is the terminal force-delete fact. A node carrying one
// may never receive new desired/secrets; only a cleanup-only control session
// (decommission ACK + heartbeat) is allowed.
type NodeCleanupTombstone struct {
	ID                     string
	NodeID                 string
	OperationID            string
	Force                  bool
	RemoteCleanupConfirmed bool
	AllowedKeyHashes       []string
	CredentialVersions     []uint32
	CreatedAt              int64
	UpdatedAt              int64
}

// ErrCleanupTombstoneConflict reports a second cleanup tombstone for a node
// whose operation id differs from the persisted terminal fact (the terminal
// fact never forks; see CreateNodeCleanupTombstone).
var ErrCleanupTombstoneConflict = errors.New("store: cleanup tombstone for node already exists with a different operation id")

// CreateNodeCleanupTombstone persists the cleanup tombstone for one node. The
// operation id is the durable identity; a second tombstone for the same node is
// allowed only when it is an idempotent retry of the SAME operation (repair-1
// L2 — the docstring previously claimed duplicates are "refused" while the
// upsert silently kept the first operation_id). A DIFFERENT operation id for an
// already-tombstoned node is refused fail-closed: the terminal fact never forks.
func (s *Store) CreateNodeCleanupTombstone(ts NodeCleanupTombstone) error {
	if ts.NodeID == "" || ts.OperationID == "" {
		return errors.New("store: cleanup tombstone requires node and operation id")
	}
	hashes, err := json.Marshal(ts.AllowedKeyHashes)
	if err != nil {
		return err
	}
	versions, err := json.Marshal(ts.CredentialVersions)
	if err != nil {
		return err
	}
	now := s.currentUnix()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin cleanup tombstone: %w", err)
	}
	defer tx.Rollback()
	var existingOp string
	err = tx.QueryRow(`SELECT operation_id FROM node_cleanup_tombstones WHERE node_id = ?`, ts.NodeID).Scan(&existingOp)
	switch {
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("store: read cleanup tombstone: %w", err)
	case err == nil && existingOp != ts.OperationID:
		return fmt.Errorf("%w: existing %q vs new %q", ErrCleanupTombstoneConflict, existingOp, ts.OperationID)
	case err == nil:
		// Idempotent retry of the SAME operation: the terminal fact is
		// unchanged; refresh the timestamp only.
		if _, err := tx.Exec(
			`UPDATE node_cleanup_tombstones SET updated_at = ? WHERE node_id = ?`,
			now, ts.NodeID,
		); err != nil {
			return fmt.Errorf("store: idempotent cleanup tombstone retry: %w", err)
		}
	default:
		if _, err := tx.Exec(
			`INSERT INTO node_cleanup_tombstones
			    (id, node_id, operation_id, force, remote_cleanup_confirmed,
			     allowed_key_hashes, credential_versions, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			orDefault(ts.ID, deterministicMessageID(ts.OperationID, "node_cleanup_tombstone")),
			ts.NodeID, ts.OperationID, boolInt(ts.Force), boolInt(ts.RemoteCleanupConfirmed),
			string(hashes), string(versions), now, now,
		); err != nil {
			return fmt.Errorf("store: create cleanup tombstone: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit cleanup tombstone: %w", err)
	}
	return nil
}

// NodeCleanupTombstone returns the tombstone for one node.
func (s *Store) NodeCleanupTombstone(nodeID string) (NodeCleanupTombstone, error) {
	var ts NodeCleanupTombstone
	var force, confirmed int
	var hashes, versions string
	err := s.db.QueryRow(
		`SELECT id, node_id, operation_id, force, remote_cleanup_confirmed,
		        allowed_key_hashes, credential_versions, created_at, updated_at
		   FROM node_cleanup_tombstones WHERE node_id = ?`, nodeID,
	).Scan(&ts.ID, &ts.NodeID, &ts.OperationID, &force, &confirmed,
		&hashes, &versions, &ts.CreatedAt, &ts.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeCleanupTombstone{}, ErrNotFound
	}
	if err != nil {
		return NodeCleanupTombstone{}, fmt.Errorf("store: get cleanup tombstone: %w", err)
	}
	ts.Force = force != 0
	ts.RemoteCleanupConfirmed = confirmed != 0
	// repair-1 L3: corrupted JSON decodes SILENTLY to nil before; a cleanup
	// tombstone with silently-empty allowed key hashes would falsely admit an
	// old key. Fail closed instead.
	if err := json.Unmarshal([]byte(hashes), &ts.AllowedKeyHashes); err != nil {
		return NodeCleanupTombstone{}, fmt.Errorf("store: decode cleanup tombstone key hashes: %w", err)
	}
	if err := json.Unmarshal([]byte(versions), &ts.CredentialVersions); err != nil {
		return NodeCleanupTombstone{}, fmt.Errorf("store: decode cleanup tombstone credential versions: %w", err)
	}
	return ts, nil
}

// MarkCleanupRemoteConfirmed records that the offline agent's deferred cleanup
// was eventually confirmed (the decommission ACK arrived) or that an operator
// accepted the bounded best-effort drop.
func (s *Store) MarkCleanupRemoteConfirmed(nodeID string) error {
	res, err := s.db.Exec(
		`UPDATE node_cleanup_tombstones
		    SET remote_cleanup_confirmed = 1, updated_at = ?
		  WHERE node_id = ?`, s.currentUnix(), nodeID,
	)
	if err != nil {
		return fmt.Errorf("store: mark cleanup remote confirmed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsCleanupOnly reports whether a node carries a terminal cleanup tombstone.
func (s *Store) IsCleanupOnly(nodeID string) (bool, error) {
	if nodeID == "" {
		return false, nil
	}
	var found int
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM node_cleanup_tombstones WHERE node_id = ?)`, nodeID,
	).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("store: cleanup-only check: %w", err)
	}
	return found == 1, nil
}

// ListCleanupTombstones returns every terminal cleanup tombstone.
func (s *Store) ListCleanupTombstones() ([]NodeCleanupTombstone, error) {
	rows, err := s.db.Query(
		`SELECT id, node_id, operation_id, force, remote_cleanup_confirmed,
		        allowed_key_hashes, credential_versions, created_at, updated_at
		   FROM node_cleanup_tombstones ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list cleanup tombstones: %w", err)
	}
	defer rows.Close()
	var out []NodeCleanupTombstone
	for rows.Next() {
		var ts NodeCleanupTombstone
		var force, confirmed int
		var hashes, versions string
		if err := rows.Scan(&ts.ID, &ts.NodeID, &ts.OperationID, &force, &confirmed,
			&hashes, &versions, &ts.CreatedAt, &ts.UpdatedAt); err != nil {
			return nil, err
		}
		ts.Force = force != 0
		ts.RemoteCleanupConfirmed = confirmed != 0
		if err := json.Unmarshal([]byte(hashes), &ts.AllowedKeyHashes); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: decode cleanup tombstone key hashes: %w", err)
		}
		if err := json.Unmarshal([]byte(versions), &ts.CredentialVersions); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: decode cleanup tombstone credential versions: %w", err)
		}
		out = append(out, ts)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// KeyRotationOperation is one durable key-rotation FSM row (v0.8 §8.3).
type KeyRotationOperation struct {
	ID                  string
	Scope               string
	OldKeyID            string
	OldKeyGeneration    uint64
	NewKeyID            string
	NewPublicKey        string
	NewGeneration       uint64
	Phase               string
	NotBeforeUnix       int64
	OverlapDeadlineUnix int64
	Certificate         string
	CreatedAt           int64
	UpdatedAt           int64
}

// CreateKeyRotationOperation persists a PREPARED rotation row.
func (s *Store) CreateKeyRotationOperation(op KeyRotationOperation) error {
	if op.ID == "" || op.Scope == "" || op.OldKeyID == "" || op.NewKeyID == "" {
		return errors.New("store: key rotation operation requires scope + old/new key ids")
	}
	if op.Phase == "" {
		op.Phase = "PREPARED"
	}
	now := s.currentUnix()
	_, err := s.db.Exec(
		`INSERT INTO key_rotation_operations
		    (id, scope, old_key_id, old_key_generation, new_key_id, new_public_key,
		     new_generation, phase, not_before_unix, overlap_deadline_unix, certificate,
		     created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.Scope, op.OldKeyID, op.OldKeyGeneration, op.NewKeyID, op.NewPublicKey,
		op.NewGeneration, op.Phase, op.NotBeforeUnix, op.OverlapDeadlineUnix, op.Certificate,
		now, now,
	)
	if err != nil {
		return fmt.Errorf("store: create key rotation operation: %w", err)
	}
	return nil
}

// AdvanceKeyRotationPhase moves a rotation operation through its exact single
// step (PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED).
func (s *Store) AdvanceKeyRotationPhase(id, next string) error {
	res, err := s.db.Exec(
		`UPDATE key_rotation_operations
		    SET phase = ?, updated_at = ?
		  WHERE id = ?`,
		next, s.currentUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: advance key rotation phase: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ForceRetireKeyRotationOperation atomically fast-forwards a rotation operation
// to RETIRED in a SINGLE UPDATE from ACKED or ACTIVE (repair-1 L1). The prior
// force-retire path wrote ACTIVE then RETIRED as two separate UPDATEs; a crash
// between them left the durable row claiming RETIRED while it was ACTIVE. One
// statement means the journal can only ever observe ACKED/ACTIVE or RETIRED,
// never a half-updated ACTIVE trailing a claimed RETIRED.
func (s *Store) ForceRetireKeyRotationOperation(id string) error {
	res, err := s.db.Exec(
		`UPDATE key_rotation_operations SET phase = 'RETIRED', updated_at = ?
		  WHERE id = ? AND phase IN ('ACKED', 'ACTIVE')`,
		s.currentUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: force retire key rotation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var phase string
		qerr := s.db.QueryRow(`SELECT phase FROM key_rotation_operations WHERE id = ?`, id).Scan(&phase)
		if errors.Is(qerr, sql.ErrNoRows) {
			return ErrNotFound
		}
		if qerr != nil {
			return qerr
		}
		return fmt.Errorf("%w: force retire refused from phase %q", ErrIllegalPhase, phase)
	}
	return nil
}

// GetKeyRotationOperation returns one rotation row by id.
func (s *Store) GetKeyRotationOperation(id string) (KeyRotationOperation, error) {
	var op KeyRotationOperation
	err := s.db.QueryRow(
		`SELECT id, scope, old_key_id, old_key_generation, new_key_id, new_public_key,
		        new_generation, phase, not_before_unix, overlap_deadline_unix, certificate,
		        created_at, updated_at
		   FROM key_rotation_operations WHERE id = ?`, id,
	).Scan(&op.ID, &op.Scope, &op.OldKeyID, &op.OldKeyGeneration, &op.NewKeyID,
		&op.NewPublicKey, &op.NewGeneration, &op.Phase, &op.NotBeforeUnix,
		&op.OverlapDeadlineUnix, &op.Certificate, &op.CreatedAt, &op.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyRotationOperation{}, ErrNotFound
	}
	if err != nil {
		return KeyRotationOperation{}, fmt.Errorf("store: get key rotation operation: %w", err)
	}
	return op, nil
}

// ListKeyRotationOperations returns every rotation row (newest first).
func (s *Store) ListKeyRotationOperations() ([]KeyRotationOperation, error) {
	rows, err := s.db.Query(
		`SELECT id, scope, old_key_id, old_key_generation, new_key_id, new_public_key,
		        new_generation, phase, not_before_unix, overlap_deadline_unix, certificate,
		        created_at, updated_at
		   FROM key_rotation_operations ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list key rotation operations: %w", err)
	}
	defer rows.Close()
	var out []KeyRotationOperation
	for rows.Next() {
		var op KeyRotationOperation
		if err := rows.Scan(&op.ID, &op.Scope, &op.OldKeyID, &op.OldKeyGeneration, &op.NewKeyID,
			&op.NewPublicKey, &op.NewGeneration, &op.Phase, &op.NotBeforeUnix,
			&op.OverlapDeadlineUnix, &op.Certificate, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// RestoreOperation is the durable record of a Controller restore entering
// RESTORE_RECONCILIATION (v0.8 §7.4).
type RestoreOperation struct {
	ID                 string
	ControllerInstance string
	ManifestSHA256     string
	SchemaVersion      int
	Phase              string
	CreatedAt          int64
	UpdatedAt          int64
}

// GetRestoreOperation returns one restore operation row by id.
func (s *Store) GetRestoreOperation(id string) (RestoreOperation, error) {
	var op RestoreOperation
	err := s.db.QueryRow(
		`SELECT id, controller_instance, manifest_sha256, schema_version, phase, created_at, updated_at
		   FROM restore_operations WHERE id = ?`, id,
	).Scan(&op.ID, &op.ControllerInstance, &op.ManifestSHA256, &op.SchemaVersion,
		&op.Phase, &op.CreatedAt, &op.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RestoreOperation{}, ErrNotFound
	}
	if err != nil {
		return RestoreOperation{}, fmt.Errorf("store: get restore operation: %w", err)
	}
	return op, nil
}

// CreateRestoreOperation persists a restore row in RESTORE_RECONCILIATION.
func (s *Store) CreateRestoreOperation(op RestoreOperation) error {
	if op.ID == "" || op.ManifestSHA256 == "" {
		return errors.New("store: restore operation requires id and manifest hash")
	}
	if op.Phase == "" {
		op.Phase = "RESTORE_RECONCILIATION"
	}
	now := s.currentUnix()
	_, err := s.db.Exec(
		`INSERT INTO restore_operations
		    (id, controller_instance, manifest_sha256, schema_version, phase, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.ControllerInstance, op.ManifestSHA256, op.SchemaVersion, op.Phase, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: create restore operation: %w", err)
	}
	return nil
}

// AdvanceRestorePhase moves a restore row through its reconciliation phases.
func (s *Store) AdvanceRestorePhase(id, next string) error {
	res, err := s.db.Exec(
		`UPDATE restore_operations SET phase = ?, updated_at = ? WHERE id = ?`,
		next, s.currentUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: advance restore phase: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsRestoreReconciling reports whether the controller is in recovery
// quarantine mode (dynamic dispatch of desired/delete/rotation is suspended).
func (s *Store) IsRestoreReconciling() (bool, error) {
	var found int
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM restore_operations WHERE phase != 'AUTHORIZED')`,
	).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("store: restore-reconciling check: %w", err)
	}
	return found == 1, nil
}

// cleanupOnlyForbiddenTypes are the orchestrating C2A message types a
// cleanup-only node must never receive. probe_outcome and restore_result were
// added in repair-2 L-B: before that a cleanup-only node could have those rows
// enqueued (QueueProbeOutcome inserts its outbox row directly), the delivery
// gate refused them, and the pump requeued them to PENDING every tick — a
// permanent claim/requeue spin.
var cleanupOnlyForbiddenTypes = map[string]bool{
	"desired":              true,
	"forward_delete":       true,
	"probe_arm":            true,
	"probe_outcome":        true,
	"restore_result":       true,
	"key_rotation_prepare": true,
	"key_rotation_commit":  true,
	"restore_reconcile":    true,
}

// DeliveryAllowed reports whether a C2A control-outbox row of messageType may be
// delivered to (or enqueued for) nodeID right now (repair-1 H2b). For the
// forbidden orchestrating types the gate refuses while the controller is in
// RESTORE_RECONCILIATION, while the node is restore-quarantined, OR while the
// node carries a terminal cleanup tombstone. A cleanup-only node additionally
// receives ONLY the node_decommission retry (the restricted-session semantics
// preserve the pre-existing pump behavior: a force-deleted node never receives
// probe_outcome / restore_result either). Delivery re-evaluates this per tick,
// so in-flight rows enqueued before a tombstone/quarantine are never delivered
// after it.
func (s *Store) DeliveryAllowed(nodeID, messageType string) (bool, error) {
	if messageType == "" {
		return true, nil
	}
	if nodeID == "" {
		return true, nil
	}
	cleanupOnly, err := s.IsCleanupOnly(nodeID)
	if err != nil {
		return false, err
	}
	if cleanupOnly {
		// A force-deleted node's only legitimate C2A content is the decommission
		// retry channel.
		return messageType == "node_decommission", nil
	}
	if !cleanupOnlyForbiddenTypes[messageType] {
		return true, nil
	}
	// Restore quarantine / RESTORE_RECONCILIATION suspends ALL automatic
	// orchestrating dispatch until an administrator reauthorizes nodes.
	reconciling, err := s.IsRestoreReconciling()
	if err != nil {
		return false, err
	}
	if reconciling {
		return false, nil
	}
	quarantined, err := s.IsNodeQuarantined(nodeID)
	if err != nil {
		return false, err
	}
	if quarantined {
		return false, nil
	}
	return true, nil
}

// EnforceCleanupOnlyEnqueue returns nil when an outbox item may be enqueued
// for a cleanup-only node (only cleanup-authorized types), and an error
// otherwise. fetchCleanupOnly is an injectable predicate (normally
// s.IsCleanupOnly) so tests can exercise the guard without a database.
func (s *Store) EnforceCleanupOnlyEnqueue(nodeID, messageType string, fetchCleanupOnly func(string) (bool, error)) error {
	if messageType == "" {
		return nil
	}
	if !cleanupOnlyForbiddenTypes[messageType] {
		return nil
	}
	if fetchCleanupOnly == nil {
		fetchCleanupOnly = s.IsCleanupOnly
	}
	reconciling, err := s.IsRestoreReconciling()
	if err != nil {
		return err
	}
	if reconciling {
		return fmt.Errorf("store: controller is in RESTORE_RECONCILIATION; refused to enqueue %q for node %q until reauthorized", messageType, nodeID)
	}
	if nodeID != "" {
		quarantined, err := s.IsNodeQuarantined(nodeID)
		if err != nil {
			return err
		}
		if quarantined {
			return fmt.Errorf("store: node %q is restore-quarantined; refused to enqueue %q until reauthorized", nodeID, messageType)
		}
	}
	cleanupOnly, err := fetchCleanupOnly(nodeID)
	if err != nil {
		return err
	}
	if cleanupOnly {
		var builder strings.Builder
		keys := make([]string, 0, len(cleanupOnlyForbiddenTypes))
		for k := range cleanupOnlyForbiddenTypes {
			keys = append(keys, k)
		}
		builder.WriteString(joinSorted(keys, ", "))
		return fmt.Errorf("store: node %q is cleanup-only; refused to enqueue %q (allowed: %s)", nodeID, messageType, builder.String())
	}
	return nil
}

// EnforceRotationBackupBarrier returns an error while any key rotation
// operation is non-terminal (NOT RETIRED), mirroring the lifecycle restore
// barrier at the BACKUP path (repair-1 S3). A backup taken mid-rotation would
// capture a half-rotated key set and a non-terminal operation journal, so it is
// refused like restore is.
func (s *Store) EnforceRotationBackupBarrier() error {
	ops, err := s.ListKeyRotationOperations()
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.Phase != "RETIRED" {
			return fmt.Errorf("store: active key rotation operation %q in phase %q blocks backup", op.ID, op.Phase)
		}
	}
	return nil
}

func joinSorted(items []string, sep string) string {
	// deterministic join for tests/diagnostics
	sorted := append([]string(nil), items...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return strings.Join(sorted, sep)
}
