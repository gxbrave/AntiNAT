// Package lifecycle owns the controller-side P14 lifecycle services: force
// delete / cleanup-only tombstones, key rotation orchestration and restore
// reconciliation. It is the durable phase-journal author for node-level
// decommission facts (v0.8 §7.3/§7.4/§8.3): every external side effect is
// preceded by a persisted row.
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// DecommissionRequest is the controller-side node decommission command.
type DecommissionRequest struct {
	NodeID             string
	OperationID        string
	Force              bool
	AllowedKeyHashes   []string
	CredentialVersions []uint32
}

// DecommissionResult reports the durable outcome.
type DecommissionResult struct {
	NodeID                 string `json:"node_id"`
	OperationID            string `json:"deletion_operation_id"`
	Mode                   string `json:"mode"`
	RemoteCleanupConfirmed bool   `json:"remote_cleanup_confirmed"`
}

// ForceDeleteNode is the controller-side force-delete lifecycle: it persists
// the cleanup tombstone (with every allowed key hash / credential version
// across a rotation overlap) BEFORE the node-deletion operation is recorded,
// and marks remote_cleanup_confirmed=false because the offline Agent has not
// yet confirmed. The node is immediately removed from the regular navigation,
// but its old key can never re-receive desired/secrets and never-reconnect
// remains unconfirmed until the bounded decommission ACK arrives.
func ForceDeleteNode(ctx context.Context, s *store.Store, req DecommissionRequest, enqueue func(store.ControlOutboxItem) error) (DecommissionResult, error) {
	node, err := s.GetNode(req.NodeID)
	if err != nil {
		return DecommissionResult{}, err
	}
	_ = node
	if req.OperationID == "" {
		return DecommissionResult{}, errors.New("lifecycle: force delete requires a deletion operation id")
	}
	tombstone := store.NodeCleanupTombstone{
		NodeID: req.NodeID, OperationID: req.OperationID, Force: true,
		RemoteCleanupConfirmed: false,
		AllowedKeyHashes:       append([]string(nil), req.AllowedKeyHashes...),
		CredentialVersions:     append([]uint32(nil), req.CredentialVersions...),
	}
	// Phrase 1 of the journal: the tombstone is the durable intent. It is the
	// authority that refuses any later desired/secrets issuance for this node.
	if err := s.CreateNodeCleanupTombstone(tombstone); err != nil {
		return DecommissionResult{}, err
	}
	// Phase 2: a best-effort node_decommission command is enqueued ONLY for the
	// cleanup-authorized type; the tombstone's enqueue guard refuses any other
	// orchestrating message for this node.
	if enqueue != nil {
		payload, _ := json.Marshal(map[string]any{
			"node_id": req.NodeID, "deletion_operation_id": req.OperationID,
			"force": true, "allowed_key_hashes": req.AllowedKeyHashes,
			"credential_versions": req.CredentialVersions,
		})
		if err := enqueue(store.ControlOutboxItem{
			OperationID:     req.OperationID,
			MessageType:     "node_decommission",
			NodeID:          req.NodeID,
			SemanticPayload: string(payload),
		}); err != nil {
			return DecommissionResult{}, err
		}
	}
	return DecommissionResult{
		NodeID: req.NodeID, OperationID: req.OperationID, Mode: "force",
		RemoteCleanupConfirmed: false,
	}, nil
}

// ConfirmRemoteCleanup marks the bounded best-effort decommission ACK as
// received. Never-reconnect remains unconfirmed until this returns without
// error.
func ConfirmRemoteCleanup(ctx context.Context, s *store.Store, nodeID string) error {
	return s.MarkCleanupRemoteConfirmed(nodeID)
}

// IsCleanupOnly is a thin, server-side predicate for the restricted session.
func IsCleanupOnly(ctx context.Context, s *store.Store, nodeID string) (bool, error) {
	return s.IsCleanupOnly(nodeID)
}

// AllowedInboundCleanupOnly reports whether an inbound A2C message type is
// accepted from a cleanup-only node's session. Only the terminal ACK and
// status/heartbeat channels are permitted; desired results and new secrets are
// structurally impossible because the issuer never sent them.
func AllowedInboundCleanupOnly(messageType string) bool {
	switch messageType {
	case "node_decommission_ack", "heartbeat", "status", "message_receipt", "operation_complete":
		return true
	}
	return false
}
