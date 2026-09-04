package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/gxbrave/AntiNAT/internal/controller/deployment"
)

// putDeploymentProfileCAS is P17's ownership transfer of the P15 profile
// storage seam. It validates/canonicalizes the typed profile and performs the
// revision check and write under one BEGIN IMMEDIATE transaction.
func (s *Store) putDeploymentProfileCAS(nodeID string, expected uint64, raw string) (DeploymentProfile, error) {
	profile, err := deployment.DecodeProfileJSON([]byte(raw))
	if err != nil {
		return DeploymentProfile{}, ErrTrafficInvalid
	}
	canonical, err := deployment.EncodeProfileJSON(profile)
	if err != nil {
		return DeploymentProfile{}, ErrTrafficInvalid
	}

	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return DeploymentProfile{}, fmt.Errorf("store: deployment profile conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return DeploymentProfile{}, fmt.Errorf("store: begin deployment profile: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var exists int
	if err := conn.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE id=?`, nodeID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return DeploymentProfile{}, ErrNodeNotFound
	} else if err != nil {
		return DeploymentProfile{}, fmt.Errorf("store: deployment profile node lookup: %w", err)
	}

	var currentRevision uint64
	var createdAt int64
	err = conn.QueryRowContext(ctx, `SELECT revision,created_at FROM node_deployment_profiles WHERE node_id=?`, nodeID).Scan(&currentRevision, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		if expected != 0 {
			return DeploymentProfile{}, ErrCASConflict
		}
		createdAt = s.currentUnix()
		if _, err := conn.ExecContext(ctx, `INSERT INTO node_deployment_profiles(node_id,profile_json,revision,created_at,updated_at) VALUES(?,?,?,?,?)`, nodeID, canonical, 1, createdAt, createdAt); err != nil {
			return DeploymentProfile{}, fmt.Errorf("store: insert deployment profile: %w", err)
		}
	} else if err != nil {
		return DeploymentProfile{}, fmt.Errorf("store: deployment profile revision lookup: %w", err)
	} else {
		if currentRevision != expected {
			return DeploymentProfile{}, ErrCASConflict
		}
		now := s.currentUnix()
		result, err := conn.ExecContext(ctx, `UPDATE node_deployment_profiles SET profile_json=?,revision=?,updated_at=? WHERE node_id=? AND revision=?`, canonical, expected+1, now, nodeID, expected)
		if err != nil {
			return DeploymentProfile{}, fmt.Errorf("store: update deployment profile: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return DeploymentProfile{}, ErrCASConflict
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return DeploymentProfile{}, fmt.Errorf("store: commit deployment profile: %w", err)
	}
	committed = true
	return s.GetDeploymentProfile(nodeID)
}
