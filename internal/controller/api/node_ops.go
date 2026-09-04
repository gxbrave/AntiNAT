package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

type nodePatchRequest struct {
	Name *string `json:"name"`
}

func (s *Server) handleNodeRoutes(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"))
	if len(parts) == 2 && parts[1] == "deployment-profile" {
		s.handleDeploymentProfile(w, r, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "enrollment-token" {
		s.handleNodeByID(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "traversal-defaults" {
		s.handleTraversalDefaults(w, r, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "traversal-detection" {
		s.handleTraversalDetection(w, r, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "delete" {
		if r.Method != http.MethodPost {
			writeError(w, 405, "BAD_REQUEST", "method not allowed")
			return
		}
		s.createNodeDeletion(w, r, parts[0])
		return
	}
	if len(parts) != 1 {
		writeError(w, 404, "NOT_FOUND", "unknown node route")
		return
	}
	if r.Method == http.MethodPatch {
		s.updateNodeName(w, r, parts[0])
		return
	}
	s.handleNodeByID(w, r)
}

func (s *Server) updateNodeName(w http.ResponseWriter, r *http.Request, nodeID string) {
	node, err := s.store.GetNode(nodeID)
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, 404, "NOT_FOUND", "node not found")
		return
	}
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "node lookup failed")
		return
	}
	if err := requireIfMatch(w, r, etagFor(node.Revision)); err != nil {
		return
	}
	var patch nodePatchRequest
	if !decodeJSON(w, r, &patch) {
		return
	}
	if patch.Name == nil || strings.TrimSpace(*patch.Name) == "" {
		writeError(w, 422, "UNPROCESSABLE_ENTITY", "name is required")
		return
	}
	updated, err := s.store.UpdateNodeNameCAS(nodeID, node.Revision, *patch.Name)
	if errors.Is(err, store.ErrCASConflict) {
		writeError(w, 412, "PRECONDITION_FAILED", "node revision changed")
		return
	}
	if errors.Is(err, store.ErrNavigationOrderConflict) {
		writeError(w, 409, "CONFLICT", "node name already exists")
		return
	}
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "node update failed")
		return
	}
	writeJSON(w, 200, s.nodeView(updated))
}

func (s *Server) handleNodeDeletionPath(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/node-deletions/"
	if !strings.HasPrefix(r.URL.Path, prefix) || len(r.URL.Path) <= len(prefix) {
		writeError(w, 404, "NOT_FOUND", "node deletion operation not found")
		return
	}
	s.handleNodeDeletion(w, r, r.URL.Path[len(prefix):])
}
func (s *Server) handleNodeDeletion(w http.ResponseWriter, r *http.Request, operationID string) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "BAD_REQUEST", "method not allowed")
		return
	}
	op, err := s.store.GetNodeDeletionOperation(operationID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "NOT_FOUND", "node deletion operation not found")
		return
	}
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "node deletion lookup failed")
		return
	}
	writeJSON(w, 200, nodeDeletionView(op))
}

func (s *Server) handleTraversalDefaults(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPut {
		writeError(w, 405, "BAD_REQUEST", "method not allowed")
		return
	}
	node, err := s.store.GetNode(nodeID)
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, 404, "NOT_FOUND", "node not found")
		return
	}
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "node lookup failed")
		return
	}
	if err := requireIfMatch(w, r, etagFor(node.Revision)); err != nil {
		return
	}
	var body struct {
		TCPStrategy string `json:"tcp_strategy"`
		UDPStrategy string `json:"udp_strategy"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	// repair-1 H2 / repair-2 P1-B: expected is the node's current revision (the
	// If-Match ETag source). The store treats the node revision as the ONLY CAS
	// axis, so a fresh node's first PUT succeeds, a stale ETag maps to 412, and
	// a defaults row that lagged after a rename/reconnect is no longer a
	// permanent-412 source. The write bumps the parent node revision atomically,
	// giving the 200 Node a fresh ETag.
	_, err = s.store.PutTraversalDefaults(nodeID, body.TCPStrategy, body.UDPStrategy, node.Revision)
	if errors.Is(err, store.ErrCASConflict) {
		writeError(w, 412, "PRECONDITION_FAILED", "defaults revision changed")
		return
	}
	if errors.Is(err, store.ErrTrafficInvalid) {
		writeError(w, 422, "UNPROCESSABLE_ENTITY", "invalid traversal defaults")
		return
	}
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "defaults update failed")
		return
	}
	updated, err := s.store.GetNode(nodeID)
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "node reload failed")
		return
	}
	writeJSON(w, 200, s.nodeView(updated))
}

func (s *Server) handleTraversalDetection(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "BAD_REQUEST", "method not allowed")
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
	op, err := s.store.CreateAPIOperation(store.APIOperation{ID: opID, Kind: "traversal_detection", NodeID: nodeID, State: "PENDING", Detail: "detection queued"})
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "detection operation failed")
		return
	}
	writeJSON(w, 202, operationView{OperationID: op.ID, State: op.State, Detail: op.Detail, CreatedAt: operationTime(now), UpdatedAt: operationTime(now)})
}

func validateForwardCapability(protoName, strategy string) error {
	if !protocol.Protocol(protoName).Valid() {
		return fmt.Errorf("unknown protocol")
	}
	if _, err := protocol.ParseStrategy(strategy); err != nil {
		return err
	}
	return nil
}
