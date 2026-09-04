package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// Node handlers (P10 Story 4). Implemented against the frozen openapi node
// surface used by the M1 walking skeleton: list/create and one-time
// enrollment-token issuance. Mutations carry Idempotency-Key (409 on
// conflict); the enrollment token is shown exactly once and never stored in
// plaintext.

// nodeView is the API-facing node (openapi Node).
type nodeView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ControlState string `json:"control_state"`
	CreatedAt    string `json:"created_at"`
	ETag         string `json:"etag"`
}

func (s *Server) nodeView(n store.Node) nodeView {
	return nodeView{
		ID: n.ID, Name: n.Name, ControlState: n.ControlState,
		CreatedAt: operationTime(n.CreatedAt), ETag: etagFor(n.Revision),
	}
}

// handleNodes implements GET/POST /api/v1/nodes.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q, ok := parseListQuery(w, r)
		if !ok {
			return
		}
		nodes, total, err := s.store.ListNodePage(q)
		if errors.Is(err, store.ErrInvalidListQuery) {
			writeError(w, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list nodes failed")
			return
		}
		items := make([]nodeView, 0, len(nodes))
		for _, n := range nodes {
			items = append(items, s.nodeView(n))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items, "page": q.Page, "page_size": q.PageSize, "total": total,
		})
	case http.MethodPost:
		// Idempotency-Key gate.
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		requestHash := requestHashOf(body)
		id, err := randomNodeID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		name := body.Name
		if name == "" {
			name = "node-" + id[:8]
		}
		rec, _, err := s.store.CreateNodeBundle(r.Context(), store.Node{ID: id, Name: name}, store.IdempotencyRecord{
			Key: key, Route: "/api/v1/nodes", Principal: "admin",
			RequestHash: requestHash, ResponseStatus: http.StatusCreated,
		})
		if errors.Is(err, store.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
			return
		}
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: nodes.name") {
				writeError(w, http.StatusConflict, "CONFLICT", "node name already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "node create failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.ResponseStatus)
		_, _ = w.Write([]byte(rec.ResponseBody))
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// handleNodeByID implements node sub-resources:
// POST /api/v1/nodes/{id}/enrollment-token
func (s *Server) handleNodeByID(w http.ResponseWriter, r *http.Request) {
	rest := r.URL.Path[len("/api/v1/nodes/"):]
	parts := splitPath(rest)
	if len(parts) != 2 || parts[1] != "enrollment-token" || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown node route")
		return
	}
	nodeID := parts[0]
	if _, err := s.store.GetNode(nodeID); err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "node not found")
		return
	}
	plain, err := s.store.CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "token issuance failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      plain,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}
