// P14 Story 5: controller-side restore/recovery phase helpers (v0.8 §7.4).
//
// RESTORE_RECONCILIATION is entered BEFORE the restored database is switched
// in: the durable restore_operations row is created, every web session is
// revoked, unused enrollment tokens are invalidated, and every node is
// quarantined (no automatic desired/delete/rotation dispatch) until an
// administrator reauthorizes it. The quarantine flag lives on nodes (0008).
package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// EnterRestoreReconciliation durably enters RESTORE_RECONCILIATION: create the
// restore operation row, revoke live web sessions, invalidate unused
// enrollment tokens and quarantine every node — one side-effect guard before
// the controller reopens on the restored database. The operation-row insert is
// idempotent (INSERT OR IGNORE on the primary key), so re-entering the SAME
// operation after a crash mid-switch (repair-1 M6a) is safe and always leaves
// the controller in RESTORE_RECONCILIATION, never silently resumed.
func (s *Store) EnterRestoreReconciliation(op RestoreOperation) error {
	if op.ID == "" || op.ManifestSHA256 == "" {
		return errors.New("store: restore reconciliation requires operation id and manifest hash")
	}
	if op.Phase == "" {
		op.Phase = "RESTORE_RECONCILIATION"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin restore reconciliation: %w", err)
	}
	defer tx.Rollback()
	now := s.currentUnix()
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO restore_operations
		    (id, controller_instance, manifest_sha256, schema_version, phase, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.ControllerInstance, op.ManifestSHA256, op.SchemaVersion, op.Phase, now, now,
	); err != nil {
		return fmt.Errorf("store: insert restore operation: %w", err)
	}
	if _, err := tx.Exec(`UPDATE web_sessions SET revoked_at = ? WHERE revoked_at IS NULL`, now); err != nil {
		return fmt.Errorf("store: revoke web sessions for restore: %w", err)
	}
	if _, err := tx.Exec(
		`UPDATE node_enrollment_tokens SET status = 'REVOKED' WHERE consumed_at IS NULL AND status = 'PENDING'`,
	); err != nil {
		return fmt.Errorf("store: revoke unused enrollment tokens for restore: %w", err)
	}
	if _, err := tx.Exec(`UPDATE nodes SET quarantined = 1,
		quarantine_restore_operation_id = ?,
		quarantine_generation = CASE
			WHEN quarantined = 1 AND quarantine_restore_operation_id = ?
			THEN quarantine_generation
			ELSE quarantine_generation + 1
		END,
		updated_at = ?`, op.ID, op.ID, now); err != nil {
		return fmt.Errorf("store: quarantine nodes for restore: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit restore reconciliation: %w", err)
	}
	return nil
}

// ReauthorizeNodeForOperation clears a node quarantine only when the named
// restore operation is AUTHORIZED and is the exact operation recorded on the
// node. The check and clear are one transaction, so stale authorization cannot
// race a newer restore operation.
func (s *Store) ReauthorizeNodeForOperation(nodeID, restoreOperationID string) error {
	if nodeID == "" || restoreOperationID == "" {
		return fmt.Errorf("%w: node and restore operation are required", ErrCASConflict)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin reauthorize node: %w", err)
	}
	defer tx.Rollback()
	var phase string
	if err := tx.QueryRow(`SELECT phase FROM restore_operations WHERE id = ?`, restoreOperationID).Scan(&phase); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: read restore operation for reauthorize: %w", err)
	}
	if phase != "AUTHORIZED" {
		return fmt.Errorf("%w: restore operation %q is %s, want AUTHORIZED", ErrIllegalPhase, restoreOperationID, phase)
	}
	res, err := tx.Exec(`UPDATE nodes SET quarantined = 0, updated_at = ?
		WHERE id = ? AND quarantined = 1 AND quarantine_restore_operation_id = ?`, s.currentUnix(), nodeID, restoreOperationID)
	if err != nil {
		return fmt.Errorf("store: reauthorize node for operation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: reauthorize node rows: %w", err)
	}
	if n == 0 {
		var quarantined, binding int
		var currentOp string
		if err := tx.QueryRow(`SELECT quarantined, quarantine_restore_operation_id FROM nodes WHERE id = ?`, nodeID).Scan(&quarantined, &currentOp); errors.Is(err, sql.ErrNoRows) {
			return ErrNodeNotFound
		} else if err != nil {
			return err
		}
		if quarantined == 0 {
			return nil
		}
		_ = binding
		return fmt.Errorf("%w: node %q is bound to restore operation %q", ErrCASConflict, nodeID, currentOp)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit reauthorize node: %w", err)
	}
	return nil
}

// ReauthorizeNode is intentionally fail-closed: callers must name the restore
// operation because a node-only clear cannot prove it is not stale.
func (s *Store) ReauthorizeNode(nodeID string) error {
	return fmt.Errorf("%w: restore operation binding required for node %q", ErrCASConflict, nodeID)
}

// IsNodeQuarantined reports the durable restore quarantine flag.
func (s *Store) IsNodeQuarantined(nodeID string) (bool, error) {
	if nodeID == "" {
		return false, nil
	}
	var q int
	err := s.db.QueryRow(`SELECT quarantined FROM nodes WHERE id = ?`, nodeID).Scan(&q)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: quarantine check: %w", err)
	}
	return q == 1, nil
}

// BackupHighWater is the manifest high-water the restore anti-rollback
// compares (desired/deletion/tombstone counts and the node revision).
type BackupHighWater struct {
	Forwards          int      `json:"forwards"`
	ForwardSpecs      int      `json:"forward_specs"`
	Deletions         int      `json:"deletions"`
	CleanupTombstones int      `json:"cleanup_tombstones"`
	NodesRevision     int64    `json:"nodes_revision"`
	CurrentKeyIDs     []string `json:"current_key_ids"`
}

// CurrentBackupHighWater computes the durable high-water values for a backup
// manifest. These are informational/anti-rollback inputs only: restore never
// auto-dispatches from them, it enters RESTORE_RECONCILIATION.
func (s *Store) CurrentBackupHighWater() (BackupHighWater, error) {
	var hw BackupHighWater
	q := func(query string, into any) error {
		row := s.db.QueryRow(query)
		if err := row.Scan(into); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return nil
	}
	if err := q(`SELECT COUNT(*) FROM forwards`, &hw.Forwards); err != nil {
		return hw, fmt.Errorf("store: backup high-water forwards: %w", err)
	}
	if err := q(`SELECT COUNT(*) FROM forward_specs`, &hw.ForwardSpecs); err != nil {
		return hw, fmt.Errorf("store: backup high-water forward_specs: %w", err)
	}
	if err := q(`SELECT COUNT(*) FROM forward_deletion_operations`, &hw.Deletions); err != nil {
		return hw, fmt.Errorf("store: backup high-water deletions: %w", err)
	}
	if err := q(`SELECT COUNT(*) FROM node_cleanup_tombstones`, &hw.CleanupTombstones); err != nil {
		return hw, fmt.Errorf("store: backup high-water cleanup tombstones: %w", err)
	}
	if err := q(`SELECT COALESCE(MAX(revision),0) FROM nodes`, &hw.NodesRevision); err != nil {
		return hw, fmt.Errorf("store: backup high-water nodes revision: %w", err)
	}
	return hw, nil
}
