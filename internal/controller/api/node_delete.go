package api

// P15 repair-1 H3: node deletion routes normal/force through the P14
// lifecycle. Force delete writes the terminal cleanup tombstone, closes an
// ESTABLISHED control session (via the App-composed closer) and enqueues the
// cleanup-guarded node_decommission command; normal delete keeps the same
// durable operation + decommission outbox transaction but never quarantines
// the node. Both keep the frozen 202 Operation response and
// /api/v1/node-deletions polling surface.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/lifecycle"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func (s *Server) createNodeDeletion(w http.ResponseWriter, r *http.Request, nodeID string) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Mode != "normal" && body.Mode != "force" {
		writeError(w, 422, "UNPROCESSABLE_ENTITY", "mode must be normal or force")
		return
	}
	if _, err := s.store.GetNode(nodeID); err != nil {
		writeError(w, 404, "NOT_FOUND", "node not found")
		return
	}
	opID, err := randomHexID()
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "operation id generation failed")
		return
	}
	now := time.Now().Unix()
	op := store.NodeDeletionOperation{ID: opID, NodeID: nodeID, Status: "PENDING", Mode: body.Mode, CreatedAt: now}

	if body.Mode == "force" {
		var terminator func(nodeID string) error
		closer := s.closeSession
		if closer != nil {
			terminator = func(n string) error {
				closer(n)
				return nil
			}
		}
		// A second force delete of an already-tombstoned node refuses before any
		// operation row is written (the terminal fact never forks; store L2).
		if _, err := lifecycle.ForceDeleteNode(context.Background(), s.store, lifecycle.DecommissionRequest{
			NodeID: nodeID, OperationID: opID, Force: true,
		}, func(item store.ControlOutboxItem) error {
			return s.store.EnqueueControlOutbox(item)
		}, terminator); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "force node deletion failed")
			return
		}
		if err := s.store.CreateNodeDeletionOperation(op); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "node deletion operation failed")
			return
		}
	} else {
		payload, _ := json.Marshal(map[string]any{"node_id": nodeID, "deletion_operation_id": opID, "force": false})
		if err := s.store.ApplyNodeDelete(op, store.ControlOutboxItem{OperationID: opID, MessageType: "node_decommission", NodeID: nodeID, SemanticPayload: string(payload), State: "PENDING"}); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "node deletion failed")
			return
		}
	}
	writeJSON(w, 202, operationView{OperationID: opID, State: "PENDING", RemoteCleanupConfirmed: false, CreatedAt: operationTime(now), UpdatedAt: operationTime(now)})
}
