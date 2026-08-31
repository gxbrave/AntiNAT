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
// the controller reopens on the restored database.
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
		`INSERT INTO restore_operations
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
	if _, err := tx.Exec(`UPDATE nodes SET quarantined = 1, updated_at = ?`, now); err != nil {
		return fmt.Errorf("store: quarantine nodes for restore: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit restore reconciliation: %w", err)
	}
	return nil
}

// ReauthorizeNode clears a single node's restore quarantine; the controller
// may then resume normal dispatch for it.
func (s *Store) ReauthorizeNode(nodeID string) error {
	res, err := s.db.Exec(
		`UPDATE nodes SET quarantined = 0, updated_at = ? WHERE id = ?`, s.currentUnix(), nodeID,
	)
	if err != nil {
		return fmt.Errorf("store: reauthorize node: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNodeNotFound
	}
	return nil
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
	Forwards        int   `json:"forwards"`
	ForwardSpecs    int   `json:"forward_specs"`
	Deletions       int   `json:"deletions"`
	CleanupTombstones int `json:"cleanup_tombstones"`
	NodesRevision   int64 `json:"nodes_revision"`
	CurrentKeyIDs   []string `json:"current_key_ids"`
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