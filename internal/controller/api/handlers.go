package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// apiServer is the minimal API server (Story 4).
type apiServer struct {
	store  *store.Store
	auth   *auth.AuthService
	health *healthState
}

// NewRouter builds the minimal admin API router.
func NewRouter(cfg RouterConfig) (http.Handler, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: store is required")
	}
	if cfg.Auth == nil {
		return nil, errors.New("api: auth service is required")
	}
	s := &apiServer{store: cfg.Store, auth: cfg.Auth, health: newHealthState()}
	s.health.setStoreReady(true)
	s.health.setAuthReady(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health.handleHealthz)
	mux.HandleFunc("/readyz", s.health.handleReadyz)

	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/v1/auth/me", s.requireAuth(s.handleMe))

	mux.HandleFunc("/api/v1/nodes", s.requireAuth(s.handleNodes))
	mux.HandleFunc("/api/v1/nodes/", s.requireAuth(s.handleNodeByID))

	mux.HandleFunc("/api/v1/forwards", s.requireAuth(s.handleForwards))
	mux.HandleFunc("/api/v1/forwards/", s.requireAuth(s.handleForwardByID))

	return mux, nil
}

// --- nodes ---

// nodeView is the API-facing node (openapi Node).
type nodeView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ControlState string `json:"control_state"`
	CreatedAt    int64  `json:"created_at"`
	ETag         string `json:"etag"`
}

func (s *apiServer) nodeView(n store.Node) nodeView {
	return nodeView{
		ID: n.ID, Name: n.Name, ControlState: n.ControlState,
		CreatedAt: n.CreatedAt, ETag: etagFor(n.Revision),
	}
}

func etagFor(revision uint64) string {
	return fmt.Sprintf("\"rev-%d\"", revision)
}

// handleNodes implements GET/POST /api/v1/nodes.
func (s *apiServer) handleNodes(w http.ResponseWriter, r *http.Request) {
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
func (s *apiServer) handleNodeByID(w http.ResponseWriter, r *http.Request) {
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

// --- forwards ---

// forwardView is the API-facing forward (openapi Forward).
type forwardView struct {
	ID              string                    `json:"id"`
	NodeID          string                    `json:"node_id"`
	Name            string                    `json:"name"`
	Protocol        string                    `json:"protocol"`
	Target          string                    `json:"target"`
	Strategy        string                    `json:"strategy"`
	DesiredRevision uint64                    `json:"desired_revision"`
	ETag            string                    `json:"etag"`
	States          protocol.ActivationStates `json:"states,omitempty"`
}

func (s *apiServer) forwardView(f store.Forward, spec protocol.ForwardSpec, states *store.ForwardRuntimeStatus) forwardView {
	view := forwardView{
		ID: f.ID, NodeID: f.NodeID, Name: f.Name, Protocol: f.Protocol,
		Target: spec.Target, Strategy: string(spec.Strategy),
		DesiredRevision: spec.DesiredRevision, ETag: etagFor(f.Revision),
	}
	if states != nil {
		var st protocol.ActivationStates
		if json.Unmarshal([]byte(states.SnapshotJSON), &st) == nil {
			view.States = st
		}
	}
	return view
}

// handleForwards implements GET/POST /api/v1/forwards.
func (s *apiServer) handleForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		forwards, err := s.store.ListForwards()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list forwards failed")
			return
		}
		items := make([]forwardView, 0, len(forwards))
		for _, f := range forwards {
			spec, err := s.latestSpec(f.ID)
			if err != nil {
				continue
			}
			states, _ := s.store.GetForwardRuntimeStatus(f.ID)
			var statesPtr *store.ForwardRuntimeStatus
			if err == nil {
				statesPtr = &states
			}
			items = append(items, s.forwardView(f, spec, statesPtr))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items, "page": 1, "page_size": len(items), "total": len(items),
		})
	case http.MethodPost:
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			NodeID     string `json:"node_id"`
			Name       string `json:"name"`
			Protocol   string `json:"protocol"`
			Target     string `json:"target"`
			Strategy   string `json:"strategy"`
			LocalPort  uint16 `json:"requested_local_port,omitempty"`
			PublicPort uint16 `json:"requested_public_port,omitempty"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		spec, err := buildForwardSpec(body.NodeID, body.Name, body.Protocol, body.Target, body.Strategy, body.LocalPort, body.PublicPort)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
		if _, err := s.store.GetNode(body.NodeID); err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "node not found")
			return
		}
		id, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		spec.ForwardID = id
		f := store.Forward{ID: id, NodeID: body.NodeID, Name: body.Name, Protocol: body.Protocol, Revision: 1}
		specRow := store.ForwardSpec{ID: "spec-" + id, ForwardID: id, Revision: 1, SpecJSON: specJSON(spec)}
		desired, err := s.buildDesiredState(body.NodeID, id, spec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired state build failed")
			return
		}
		if _, err := s.store.CreateForward(f); err != nil {
			writeError(w, http.StatusConflict, "CONFLICT", "forward name already exists on node")
			return
		}
		if err := s.store.CreateForwardSpec(specRow); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "spec persist failed")
			return
		}
		if err := s.enqueueDesired(body.NodeID, desired); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired enqueue failed")
			return
		}
		got, _ := s.store.GetForward(id)
		writeJSON(w, http.StatusCreated, s.forwardView(got, spec, nil))
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// handleForwardByID implements GET/PATCH/DELETE /api/v1/forwards/{id} and
// GET /api/v1/forward-deletions/{operation_id}.
func (s *apiServer) handleForwardByID(w http.ResponseWriter, r *http.Request) {
	rest := r.URL.Path[len("/api/v1/forwards/"):]
	parts := splitPath(rest)
	if len(parts) == 2 && parts[0] == "forward-deletions" {
		s.handleDeletionPoll(w, r, parts[1])
		return
	}
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown forward route")
		return
	}
	id := parts[0]

	// Precondition precedence (docs/error-codes.md §5): a missing If-Match is
	// 428 even before resource lookup; a mismatched value on an existing
	// resource is 412.
	if r.Method == http.MethodPatch || r.Method == http.MethodDelete {
		if r.Header.Get("If-Match") == "" {
			writeError(w, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "If-Match is required")
			return
		}
	}

	f, err := s.store.GetForward(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "forward not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		spec, err := s.latestSpec(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "spec read failed")
			return
		}
		states, _ := s.store.GetForwardRuntimeStatus(id)
		var statesPtr *store.ForwardRuntimeStatus
		if err == nil {
			statesPtr = &states
		}
		writeJSON(w, http.StatusOK, s.forwardView(f, spec, statesPtr))
	case http.MethodPatch:
		if err := requireIfMatch(w, r, etagFor(f.Revision)); err != nil {
			return
		}
		var body struct {
			Target string `json:"target"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Target == "" {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "target is required")
			return
		}
		spec, err := s.latestSpec(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "spec read failed")
			return
		}
		spec.Target = body.Target
		spec.DesiredRevision++
		newSpec := store.ForwardSpec{
			ID:        "spec-" + id + "-" + strconv.FormatUint(spec.DesiredRevision, 10),
			ForwardID: id, Revision: spec.DesiredRevision, SpecJSON: specJSON(spec),
		}
		desired, err := s.buildDesiredState(f.NodeID, id, spec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired build failed")
			return
		}
		opID, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		// Atomic: new spec + parent revision bump + desired outbox in one
		// transaction (frozen state-model §3: intent before side effect).
		if err := s.store.ApplyForwardDesired(newSpec, store.ControlOutboxItem{
			OperationID: opID, MessageType: "desired", NodeID: f.NodeID,
			SemanticPayload: desiredJSON(desired), State: "PENDING",
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired apply failed")
			return
		}
		got, _ := s.store.GetForward(id)
		writeJSON(w, http.StatusOK, s.forwardView(got, spec, nil))
	case http.MethodDelete:
		if err := requireIfMatch(w, r, etagFor(f.Revision)); err != nil {
			return
		}
		opID, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		desired, err := s.buildDeleteDesired(f.NodeID, id, opID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired build failed")
			return
		}
		if err := s.store.ApplyForwardDelete(store.ForwardDeletionOperation{
			ID: opID, ForwardID: id, Status: "PENDING", DesiredRevision: f.Revision,
		}, store.ControlOutboxItem{
			OperationID: opID, MessageType: "desired", NodeID: f.NodeID,
			SemanticPayload: desiredJSON(desired), State: "PENDING",
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "deletion op failed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"operation_id": opID, "state": "PENDING",
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// requireIfMatch enforces the frozen ETag precondition: 412 on mismatch.
// The caller checks presence (428) before resource lookup.
func requireIfMatch(w http.ResponseWriter, r *http.Request, current string) error {
	if r.Header.Get("If-Match") != current {
		writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "ETag mismatch")
		return errors.New("etag mismatch")
	}
	return nil
}

// handleDeletionPoll implements GET /api/v1/forward-deletions/{operation_id}.
func (s *apiServer) handleDeletionPoll(w http.ResponseWriter, r *http.Request, opID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
	op, err := s.store.GetForwardDeletionOperation(opID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "deletion operation not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"operation_id": op.ID, "state": op.Status,
	})
}

// --- helpers ---

func (s *apiServer) latestSpec(forwardID string) (protocol.ForwardSpec, error) {
	row, err := s.store.LatestForwardSpec(forwardID)
	if err != nil {
		return protocol.ForwardSpec{}, err
	}
	var spec protocol.ForwardSpec
	if err := json.Unmarshal([]byte(row.SpecJSON), &spec); err != nil {
		return protocol.ForwardSpec{}, err
	}
	return spec, nil
}

// enqueueDesired queues a full desired snapshot for the node.
func (s *apiServer) enqueueDesired(nodeID string, desired protocol.DesiredState) error {
	opID, err := randomHexID()
	if err != nil {
		return err
	}
	return s.store.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: opID, MessageType: "desired", NodeID: nodeID,
		SemanticPayload: desiredJSON(desired), State: "PENDING",
	})
}

// buildDesiredState builds the full desired snapshot including the new spec.
func (s *apiServer) buildDesiredState(nodeID, newForwardID string, newSpec protocol.ForwardSpec) (protocol.DesiredState, error) {
	forwards, err := s.store.ListForwards()
	if err != nil {
		return protocol.DesiredState{}, err
	}
	d := protocol.DesiredState{NodeID: nodeID}
	for _, f := range forwards {
		if f.NodeID != nodeID {
			continue
		}
		if f.ID == newForwardID {
			d.Forwards = append(d.Forwards, newSpec)
			continue
		}
		spec, err := s.latestSpec(f.ID)
		if err != nil {
			continue
		}
		d.Forwards = append(d.Forwards, spec)
	}
	return d, d.Validate()
}

// buildDeleteDesired builds a desired snapshot with the forward ABSENT.
func (s *apiServer) buildDeleteDesired(nodeID, forwardID, deletionOpID string) (protocol.DesiredState, error) {
	forwards, err := s.store.ListForwards()
	if err != nil {
		return protocol.DesiredState{}, err
	}
	d := protocol.DesiredState{NodeID: nodeID}
	for _, f := range forwards {
		if f.NodeID != nodeID {
			continue
		}
		if f.ID == forwardID {
			// The ABSENT entry carries the last valid spec fields (the
			// frozen ForwardSpec validation requires a concrete target and
			// protocol even for deletions) plus the deletion operation id.
			last, err := s.latestSpec(f.ID)
			if err != nil {
				return protocol.DesiredState{}, err
			}
			last.Presence = protocol.PresenceAbsent
			last.DeletionOperationID = deletionOpID
			d.Forwards = append(d.Forwards, last)
			continue
		}
		spec, err := s.latestSpec(f.ID)
		if err != nil {
			continue
		}
		d.Forwards = append(d.Forwards, spec)
	}
	return d, d.Validate()
}

func buildForwardSpec(nodeID, name, proto, target, strategy string, localPort, publicPort uint16) (protocol.ForwardSpec, error) {
	p := protocol.Protocol(proto)
	if !p.Valid() {
		return protocol.ForwardSpec{}, fmt.Errorf("unknown protocol %q", proto)
	}
	st, err := protocol.ParseStrategy(strategy)
	if err != nil {
		return protocol.ForwardSpec{}, err
	}
	return protocol.ForwardSpec{
		ForwardID: "", Name: name, Protocol: p, Target: target, Strategy: st,
		RequestedLocalPort: localPort, RequestedPublicPort: publicPort,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}, nil
}

func specJSON(spec protocol.ForwardSpec) string {
	raw, _ := json.Marshal(spec)
	return string(raw)
}

func desiredJSON(d protocol.DesiredState) string {
	raw, _ := json.Marshal(d)
	return string(raw)
}

func splitPath(rest string) []string {
	var out []string
	cur := ""
	for _, c := range rest {
		if c == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func randomHexID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requestHashOf hashes the canonical JSON of the decoded request body.
func requestHashOf(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
