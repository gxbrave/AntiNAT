package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func (s *Server) handleForwardRoutes(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(r.URL.Path, "/api/v1/forwards/"))
	if len(parts) == 2 && parts[1] == "retry" {
		s.handleForwardAction(w, r, parts[0], "retry")
		return
	}
	if len(parts) == 2 && parts[1] == "force-publish" {
		s.handleForwardAction(w, r, parts[0], "force-publish")
		return
	}
	if len(parts) == 2 && parts[1] == "force-cutover" {
		s.handleForwardAction(w, r, parts[0], "force-cutover")
		return
	}
	if len(parts) != 1 {
		writeError(w, 404, "NOT_FOUND", "unknown forward route")
		return
	}
	s.handleForwardByID(w, r)
}

func (s *Server) handleForwardAction(w http.ResponseWriter, r *http.Request, id, action string) {
	f, err := s.store.GetForward(id)
	if errors.Is(err, store.ErrForwardNotFound) {
		writeError(w, 404, "NOT_FOUND", "forward not found")
		return
	}
	if err != nil {
		writeError(w, 500, "INTERNAL_ERROR", "forward lookup failed")
		return
	}
	if r.Method == http.MethodPost && (action == "force-publish" || action == "force-cutover") {
		if err := requireIfMatch(w, r, etagFor(f.Revision)); err != nil {
			return
		}
	}
	if action == "force-cutover" {
		writeError(w, 501, "NOT_IMPLEMENTED", "force cutover is not implemented in this build")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "BAD_REQUEST", "method not allowed")
		return
	}
	if action == "force-publish" {
		spec, err := s.latestSpec(id)
		if err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "spec read failed")
			return
		}
		states, err := s.store.GetForwardRuntimeStatus(id)
		if err != nil {
			writeError(w, 409, "CONFLICT", "forward runtime state is unavailable")
			return
		}
		var snapshot protocol.ActivationStates
		if json.Unmarshal([]byte(states.SnapshotJSON), &snapshot) != nil {
			writeError(w, 500, "INTERNAL_ERROR", "forward runtime state is invalid")
			return
		}
		snapshot.PublicationState = "PUBLISHED_UNVERIFIED"
		if err := s.store.SetForwardRuntimeStatus(id, states.ActivationID, f.Revision, func() string { raw, _ := json.Marshal(snapshot); return string(raw) }()); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "force publish failed")
			return
		}
		_ = spec
		_ = s.store.AppendAudit("admin", "UnverifiedEndpointPublished", id, `{"publication_state":"PUBLISHED_UNVERIFIED"}`)
		writeJSON(w, 200, s.forwardView(f, spec, &states))
		return
	}
	if action == "retry" {
		opID, err := randomHexID()
		if err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "operation id generation failed")
			return
		}
		spec, err := s.latestSpec(id)
		if err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "spec read failed")
			return
		}
		desired, err := s.buildDesiredState(f.NodeID, id, spec)
		if err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "desired state build failed")
			return
		}
		payload := desiredJSON(desired)
		if err := s.store.EnqueueControlOutbox(store.ControlOutboxItem{OperationID: opID, MessageType: "desired", NodeID: f.NodeID, SemanticPayload: payload, State: "PENDING"}); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "retry enqueue failed")
			return
		}
		now := time.Now().Unix()
		if _, err := s.store.CreateAPIOperation(store.APIOperation{ID: opID, Kind: "forward_retry", ForwardID: id, State: "PENDING", Detail: "retry queued"}); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "retry operation failed")
			return
		}
		writeJSON(w, 202, operationView{OperationID: opID, State: "PENDING", Detail: "retry queued", CreatedAt: operationTime(now), UpdatedAt: operationTime(now)})
	}
}

func _forwardProtocolValidation(protoName, strategy string) error {
	if !protocol.Protocol(protoName).Valid() {
		return errors.New("invalid protocol")
	}
	_, err := protocol.ParseStrategy(strategy)
	return err
}
