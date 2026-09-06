package api

import (
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// operationView is the frozen OpenAPI Operation shape.
type operationView struct {
	OperationID            string `json:"operation_id"`
	State                  string `json:"state"`
	Detail                 string `json:"detail,omitempty"`
	RemoteCleanupConfirmed bool   `json:"remote_cleanup_confirmed"`
	CreatedAt              string `json:"created_at,omitempty"`
	UpdatedAt              string `json:"updated_at,omitempty"`
}

func operationTime(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func (s *Server) nodeDeletionView(op store.NodeDeletionOperation) operationView {
	confirmed := false
	if op.Mode == "force" {
		if tombstone, err := s.store.NodeCleanupTombstone(op.NodeID); err == nil {
			confirmed = tombstone.RemoteCleanupConfirmed
		}
	}
	return operationView{OperationID: op.ID, State: op.Status, RemoteCleanupConfirmed: confirmed,
		CreatedAt: operationTime(op.CreatedAt), UpdatedAt: operationTime(maxInt64(op.CreatedAt, op.CompletedAt))}
}

func forwardDeletionView(op store.ForwardDeletionOperation) operationView {
	return operationView{OperationID: op.ID, State: op.Status, RemoteCleanupConfirmed: op.Status == "COMPLETED",
		CreatedAt: operationTime(op.CreatedAt), UpdatedAt: operationTime(maxInt64(op.CreatedAt, op.CompletedAt))}
}

func maxInt64(a, b int64) int64 {
	if b > a {
		return b
	}
	return a
}
