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
	"errors"
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
	node, err := s.store.GetNode(nodeID)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", "node not found")
		return
	}
	if err := requireIfMatch(w, r, etagFor(node.Revision)); err != nil {
		return
	}
	if body.Mode == "normal" && s.rejectCleanupOnly(w, nodeID) {
		return
	}
	// repair-2 P2-B: an already-tombstoned node's force delete is an idempotent
	// re-entry. The terminal fact (cleanup tombstone) never forks; a second
	// request with a fresh operation id would be just so much 500-ing. Return
	// the existing correlated operation as 202 (repeatable and pollable) so
	// clients converge on the real deletion state. If the terminal fact exists
	// but its operation row is gone (a pre-existing orphan), refuse with an
	// explicit client-visible conflict — never a raw INTERNAL_ERROR.
	if body.Mode == "force" {
		if tombstone, tsErr := s.store.NodeCleanupTombstone(nodeID); tsErr == nil {
			if existingOp, err := s.store.GetNodeDeletionOperation(tombstone.OperationID); err == nil {
				writeJSON(w, 202, s.nodeDeletionView(existingOp))
				return
			}
			writeError(w, 409, "CONFLICT", "node is already being force-deleted")
			return
		} else if !errors.Is(tsErr, store.ErrNotFound) {
			writeError(w, 500, "INTERNAL_ERROR", "node deletion lookup failed")
			return
		}
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
		// repair-2 P2-A: durable intent BEFORE side effect. The operation row is
		// the phase journal; it is written first so a failure in the tombstone/
		// outbox phase leaves a POLLABLE PENDING operation — never a tombstone
		// or outbox without a pollable operation. (The old order wrote the
		// tombstone first and could strand a tombstone with no operation row.)
		if err := s.store.CreateNodeDeletionOperation(op); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "node deletion operation failed")
			return
		}
		if _, err := lifecycle.ForceDeleteNode(context.Background(), s.store, lifecycle.DecommissionRequest{
			NodeID: nodeID, OperationID: opID, Force: true,
		}, func(item store.ControlOutboxItem) error {
			return s.store.EnqueueControlOutbox(item)
		}, terminator); err != nil {
			// A concurrent delete that won the terminal fact makes this intent
			// stale: drop the orphaned operation row (the winner's operation is
			// the authoritative one). Any other failure keeps the pollable
			// PENDING operation and the correlated tombstone.
			if errors.Is(err, store.ErrCleanupTombstoneConflict) {
				_ = s.store.DeleteNodeDeletionOperation(opID)
				if tombstone, tsErr := s.store.NodeCleanupTombstone(nodeID); tsErr == nil {
					if existingOp, opErr := s.store.GetNodeDeletionOperation(tombstone.OperationID); opErr == nil {
						writeJSON(w, http.StatusAccepted, s.nodeDeletionView(existingOp))
						return
					}
				}
				writeError(w, http.StatusConflict, "CONFLICT", "node is already being force-deleted")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "force node deletion failed")
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
