package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreateNodeDeletionOperationCAS records a force-delete intent only when the
// caller still owns the node revision. The operation insert is serialized with
// BEGIN IMMEDIATE so two force requests cannot both pass a read-only revision
// check before the lifecycle tombstone phase.
func (s *Store) CreateNodeDeletionOperationCAS(op NodeDeletionOperation, expectedRevision uint64) error {
	if op.ID == "" || op.NodeID == "" || op.Status == "" || op.Mode == "" {
		return ErrTrafficInvalid
	}
	return s.withNodeDeleteCAS(func(ctx context.Context, conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx, `
			INSERT INTO node_deletion_operations (id, node_id, status, mode, created_at)
			SELECT ?, ?, ?, ?, ?
			 WHERE EXISTS (
				SELECT 1 FROM nodes n
				 WHERE n.id = ? AND n.revision = ?
				   AND NOT EXISTS (SELECT 1 FROM node_cleanup_tombstones t WHERE t.node_id = n.id)
			)`,
			op.ID, op.NodeID, op.Status, op.Mode, s.currentUnix(), op.NodeID, expectedRevision)
		if err != nil {
			return fmt.Errorf("store: create CAS node deletion operation: %w", err)
		}
		if affected, err := res.RowsAffected(); err != nil {
			return err
		} else if affected != 1 {
			return s.classifyNodeDeleteCAS(ctx, conn, op.NodeID, expectedRevision)
		}
		return nil
	})
}

// ApplyNodeDeleteCAS atomically verifies the node revision, creates a normal
// deletion operation and enqueues its decommission command. A second pending
// normal intent for the same node is rejected inside the same write transaction.
func (s *Store) ApplyNodeDeleteCAS(op NodeDeletionOperation, outbox ControlOutboxItem, expectedRevision uint64) error {
	if op.ID == "" || op.NodeID == "" || op.Status == "" || op.Mode == "" {
		return ErrTrafficInvalid
	}
	if op.Mode != "normal" {
		return ErrTrafficInvalid
	}
	return s.withNodeDeleteCAS(func(ctx context.Context, conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx, `
			INSERT INTO node_deletion_operations (id, node_id, status, mode, created_at)
			SELECT ?, ?, ?, ?, ?
			 WHERE EXISTS (
				SELECT 1 FROM nodes n
				 WHERE n.id = ? AND n.revision = ?
				   AND NOT EXISTS (SELECT 1 FROM node_cleanup_tombstones t WHERE t.node_id = n.id)
				   AND NOT EXISTS (
						SELECT 1 FROM node_deletion_operations d
						 WHERE d.node_id = n.id AND d.mode = 'normal'
						   AND d.status IN ('PENDING', 'IN_PROGRESS', 'RECEIVED', 'APPLYING', 'INTENT_PERSISTED')
				   )
			)`,
			op.ID, op.NodeID, op.Status, op.Mode, s.currentUnix(), op.NodeID, expectedRevision)
		if err != nil {
			return fmt.Errorf("store: create normal CAS node deletion: %w", err)
		}
		if affected, err := res.RowsAffected(); err != nil {
			return err
		} else if affected != 1 {
			return s.classifyNodeDeleteCAS(ctx, conn, op.NodeID, expectedRevision)
		}
		if err := insertOutboxExec(ctx, conn, outbox); err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) withNodeDeleteCAS(fn func(context.Context, *sql.Conn) error) error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: node delete CAS conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin node delete CAS: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err := fn(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit node delete CAS: %w", err)
	}
	committed = true
	return nil
}

func (s *Store) classifyNodeDeleteCAS(ctx context.Context, conn *sql.Conn, nodeID string, expectedRevision uint64) error {
	var exists int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id = ?)`, nodeID).Scan(&exists); err != nil {
		return fmt.Errorf("store: classify node delete CAS: %w", err)
	}
	if exists == 0 {
		return ErrNodeNotFound
	}
	var tombstone int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM node_cleanup_tombstones WHERE node_id = ?)`, nodeID).Scan(&tombstone); err != nil {
		return fmt.Errorf("store: classify node tombstone CAS: %w", err)
	}
	if tombstone == 1 {
		return ErrCleanupTombstoneConflict
	}
	var revision uint64
	if err := conn.QueryRowContext(ctx, `SELECT revision FROM nodes WHERE id = ?`, nodeID).Scan(&revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNodeNotFound
		}
		return err
	}
	if revision != expectedRevision {
		return ErrCASConflict
	}
	return ErrCASConflict
}
