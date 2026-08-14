package api

import (
	"encoding/json"
	"net/http"
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
	CreatedAt    int64  `json:"created_at"`
	ETag         string `json:"etag"`
}

func (s *Server) nodeView(n store.Node) nodeView {
	return nodeView{
		ID: n.ID, Name: n.Name, ControlState: n.ControlState,
		CreatedAt: n.CreatedAt, ETag: etagFor(n.Revision),
	}
}

// handleNodes implements GET/POST /api/v1/nodes.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes, err := s.store.ListNodes()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list nodes failed")
			return
		}
		items := make([]nodeView, 0, len(nodes))
		for _, n := range nodes {
			items = append(items, s.nodeView(n))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items, "page": 1, "page_size": len(items), "total": len(items),
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
		// Check for an existing idempotency record first (replay or conflict).
		if existing, err := s.store.GetIdempotency(key); err == nil {
			if existing.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(existing.ResponseStatus)
			_, _ = w.Write([]byte(existing.ResponseBody))
			return
		}
		id, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		name := body.Name
		if name == "" {
			name = "node-" + id[:8]
		}
		if err := s.store.CreateNode(store.Node{ID: id, Name: name}); err != nil {
			writeError(w, http.StatusConflict, "CONFLICT", "node name already exists")
			return
		}
		n, err := s.store.GetNode(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "node readback failed")
			return
		}
		view := s.nodeView(n)
		raw, _ := json.Marshal(view)
		_, _, _ = s.store.StoreIdempotency(store.IdempotencyRecord{
			Key: key, Route: "/api/v1/nodes", Principal: "admin",
			RequestHash: requestHash, ResponseStatus: http.StatusCreated, ResponseBody: string(raw),
		})
		writeJSON(w, http.StatusCreated, view)
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
		"expires_at": time.Now().Add(time.Hour).Unix(),
	})
}
