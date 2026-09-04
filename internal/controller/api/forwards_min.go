package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// Forward handlers (P10 Story 4). Implemented against the frozen openapi
// forward surface used by the M1 walking skeleton: list/create, target hot
// update (PATCH, revision-bumped), online delete (DELETE with a durable
// deletion operation and If-Match) and deletion polling. Every mutation uses
// ETag/If-Match (428 missing, 412 stale); creates carry Idempotency-Key.

// forwardView is the API-facing forward (openapi Forward).
type forwardView struct {
	ID                     string                    `json:"id"`
	NodeID                 string                    `json:"node_id"`
	Name                   string                    `json:"name"`
	Protocol               string                    `json:"protocol"`
	Target                 string                    `json:"target"`
	Strategy               string                    `json:"strategy"`
	SourceInterface        string                    `json:"source_interface,omitempty"`
	RequestedLocalPort     uint16                    `json:"requested_local_port,omitempty"`
	RequestedPublicPort    uint16                    `json:"requested_public_port,omitempty"`
	ManualExpectedEndpoint string                    `json:"manual_expected_endpoint,omitempty"`
	RateLimitBPS           uint64                    `json:"rate_limit_bps,omitempty"`
	DetailedStats          bool                      `json:"detailed_stats,omitempty"`
	PublishScheme          string                    `json:"publish_scheme,omitempty"`
	PublishedHost          string                    `json:"published_host,omitempty"`
	CustomURITemplate      string                    `json:"custom_uri_template,omitempty"`
	DesiredRevision        uint64                    `json:"desired_revision"`
	ETag                   string                    `json:"etag"`
	States                 protocol.ActivationStates `json:"states,omitempty"`
	EvidenceSource         string                    `json:"evidence_source,omitempty"`
	EvidenceUpdatedAt      string                    `json:"evidence_updated_at,omitempty"`
	EvidenceActivationID   string                    `json:"evidence_activation_id,omitempty"`
}

func (s *Server) forwardView(f store.Forward, spec protocol.ForwardSpec, states *store.ForwardRuntimeStatus) forwardView {
	view := forwardView{
		ID: f.ID, NodeID: f.NodeID, Name: f.Name, Protocol: f.Protocol,
		Target: spec.Target, Strategy: string(spec.Strategy),
		SourceInterface: spec.SourceInterface, RequestedLocalPort: spec.RequestedLocalPort,
		RequestedPublicPort: spec.RequestedPublicPort, ManualExpectedEndpoint: spec.ManualExpectedEndpoint,
		RateLimitBPS: spec.RateLimitBPS, DetailedStats: spec.DetailedStats,
		PublishScheme: spec.PublishScheme, PublishedHost: spec.PublishedHost,
		CustomURITemplate: spec.CustomURITemplate,
		DesiredRevision:   spec.DesiredRevision, ETag: etagFor(f.Revision),
	}
	if states != nil {
		var st protocol.ActivationStates
		if json.Unmarshal([]byte(states.SnapshotJSON), &st) == nil {
			view.States = st
			view.EvidenceSource = "forward_runtime_status"
			view.EvidenceUpdatedAt = operationTime(states.UpdatedAt)
			view.EvidenceActivationID = states.ActivationID
		}
	}
	return view
}

// handleForwards implements GET/POST /api/v1/forwards.
func (s *Server) handleForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q, ok := parseListQuery(w, r)
		if !ok {
			return
		}
		forwards, total, err := s.store.ListForwardPage(q)
		if errors.Is(err, store.ErrInvalidListQuery) {
			writeError(w, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list forwards failed")
			return
		}
		items := make([]forwardView, 0, len(forwards))
		for _, f := range forwards {
			spec, err := s.latestSpec(f.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "spec read failed")
				return
			}
			states, stateErr := s.store.GetForwardRuntimeStatus(f.ID)
			var statesPtr *store.ForwardRuntimeStatus
			if stateErr == nil {
				statesPtr = &states
			}
			items = append(items, s.forwardView(f, spec, statesPtr))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items, "page": q.Page, "page_size": q.PageSize, "total": total,
		})
	case http.MethodPost:
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			NodeID                 string `json:"node_id"`
			Name                   string `json:"name"`
			Protocol               string `json:"protocol"`
			Target                 string `json:"target"`
			Strategy               string `json:"strategy"`
			LocalPort              uint16 `json:"requested_local_port,omitempty"`
			PublicPort             uint16 `json:"requested_public_port,omitempty"`
			SourceInterface        string `json:"source_interface"`
			ManualExpectedEndpoint string `json:"manual_expected_endpoint"`
			RateLimitBPS           uint64 `json:"rate_limit_bps,omitempty"`
			DetailedStats          bool   `json:"detailed_stats,omitempty"`
			PublishScheme          string `json:"publish_scheme"`
			PublishedHost          string `json:"published_host"`
			CustomURITemplate      string `json:"custom_uri_template"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		// Idempotency is checked before any forward side effect. The server
		// mutex closes the in-process race between the check and persistence;
		// the durable record remains the replay/conflict authority.
		s.idempotencyMu.Lock()
		defer s.idempotencyMu.Unlock()
		principal := "admin"
		if user, ok := s.currentUser(r); ok && user.ID != "" {
			principal = user.ID
		}
		requestHash := requestHashOf(body)
		if existing, err := s.store.GetIdempotency(key); err == nil && existing.ExpiresAt > time.Now().Unix() {
			if existing.Route != "/api/v1/forwards" || existing.Principal != principal || existing.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
				return
			}
			if existing.ResponseBody == "" {
				writeError(w, http.StatusConflict, "CONFLICT", "request with this Idempotency-Key is in progress")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(existing.ResponseStatus)
			_, _ = w.Write([]byte(existing.ResponseBody))
			return
		}
		spec, err := buildForwardSpec(body.NodeID, body.Name, body.Protocol, body.Target, body.Strategy, body.LocalPort, body.PublicPort)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
		spec.SourceInterface = strings.TrimSpace(body.SourceInterface)
		spec.ManualExpectedEndpoint = strings.TrimSpace(body.ManualExpectedEndpoint)
		spec.RateLimitBPS = body.RateLimitBPS
		spec.DetailedStats = body.DetailedStats
		spec.PublishScheme = strings.TrimSpace(body.PublishScheme)
		spec.PublishedHost = strings.TrimSpace(body.PublishedHost)
		spec.CustomURITemplate = strings.TrimSpace(body.CustomURITemplate)
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
		if err := validateForwardCreateSpec(spec); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
		activation := protocol.ActivationID(id, 1)
		f := store.Forward{ID: id, NodeID: body.NodeID, Name: body.Name, Protocol: body.Protocol, CurrentActivationID: hex.EncodeToString(activation[:]), Revision: 1}
		specRow := store.ForwardSpec{ID: "spec-" + id, ForwardID: id, Revision: 1, SpecJSON: specJSON(spec)}
		// Build all derived values before opening the atomic store bundle. The
		// helper explicitly includes the not-yet-persisted forward, so a failure
		// cannot leave a parent/spec without its desired command.
		desired, err := s.buildDesiredState(body.NodeID, id, spec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired state build failed")
			return
		}
		opID, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "operation id generation failed")
			return
		}
		outbox := store.ControlOutboxItem{
			OperationID: opID, MessageType: "desired", NodeID: body.NodeID,
			SemanticPayload: desiredJSON(desired), State: "PENDING",
		}
		view := s.forwardView(f, spec, nil)
		raw, _ := json.Marshal(view)
		stored, replayed, err := s.store.CreateForwardBundle(r.Context(), f, specRow, outbox, store.IdempotencyRecord{
			Key: key, Route: "/api/v1/forwards", Principal: principal,
			RequestHash: requestHash, ResponseStatus: http.StatusCreated, ResponseBody: string(raw),
		})
		if err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
			} else if errors.Is(err, store.ErrForwardNameConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "forward name already exists on node")
			} else {
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "forward create transaction failed")
			}
			return
		}
		if replayed {
			if stored.ResponseBody == "" {
				writeError(w, http.StatusConflict, "CONFLICT", "request with this Idempotency-Key is in progress")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stored.ResponseStatus)
			_, _ = w.Write([]byte(stored.ResponseBody))
			return
		}
		writeJSON(w, http.StatusCreated, view)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// handleForwardByID implements GET/PATCH/DELETE /api/v1/forwards/{id} and
// GET /api/v1/forward-deletions/{operation_id}.
func (s *Server) handleForwardByID(w http.ResponseWriter, r *http.Request) {
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
		states, stateErr := s.store.GetForwardRuntimeStatus(id)
		var statesPtr *store.ForwardRuntimeStatus
		if stateErr == nil {
			statesPtr = &states
		}
		writeJSON(w, http.StatusOK, s.forwardView(f, spec, statesPtr))
	case http.MethodPatch:
		if err := requireIfMatch(w, r, etagFor(f.Revision)); err != nil {
			return
		}
		var body struct {
			Target             *string `json:"target"`
			Name               *string `json:"name"`
			RateLimitBPS       *uint64 `json:"rate_limit_bps"`
			DetailedStats      *bool   `json:"detailed_stats"`
			DisconnectExisting bool    `json:"disconnect_existing"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Target == nil && body.Name == nil && body.RateLimitBPS == nil && body.DetailedStats == nil {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "at least one supported field is required")
			return
		}
		spec, err := s.latestSpec(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "spec read failed")
			return
		}
		if body.Target != nil {
			spec.Target = strings.TrimSpace(*body.Target)
		}
		if body.Name != nil {
			name := strings.TrimSpace(*body.Name)
			if name == "" {
				writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name must not be empty")
				return
			}
			spec.Name = name
		}
		if body.RateLimitBPS != nil {
			spec.RateLimitBPS = *body.RateLimitBPS
		}
		if body.DetailedStats != nil {
			spec.DetailedStats = *body.DetailedStats
		}
		if err := validateForwardCreateSpec(spec); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
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
			if errors.Is(err, store.ErrCASConflict) {
				writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "forward revision changed")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "desired apply failed")
			return
		}
		got, _ := s.store.GetForward(id)
		writeJSON(w, http.StatusOK, s.forwardView(got, spec, nil))
	case http.MethodDelete:
		// Once a delete intent has fenced and advanced the parent revision,
		// repeated DELETEs replay its operation id. This is deliberately checked
		// before If-Match so a retry carrying the original ETag is idempotent.
		if previous, findErr := s.store.LatestForwardDeletion(id); findErr == nil && previous.DesiredRevision+1 == f.Revision {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"operation_id": previous.ID, "state": previous.Status,
			})
			return
		}
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
			if errors.Is(err, store.ErrCASConflict) {
				writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "forward revision changed")
				return
			}
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
	if r == nil || strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		writeError(w, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "If-Match is required")
		return errors.New("if-match required")
	}
	if r.Header.Get("If-Match") != current {
		writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "ETag mismatch")
		return errors.New("etag mismatch")
	}
	return nil
}

// handleDeletionPoll implements GET /api/v1/forward-deletions/{operation_id}.
func (s *Server) handleDeletionPoll(w http.ResponseWriter, r *http.Request, opID string) {
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

// handleDeletionPollPath is the frozen top-level deletion polling route:
// GET /api/v1/forward-deletions/{operation_id}.
func (s *Server) handleDeletionPollPath(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/forward-deletions/"
	if len(r.URL.Path) <= len(prefix) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "deletion operation not found")
		return
	}
	s.handleDeletionPoll(w, r, r.URL.Path[len(prefix):])
}

// --- helpers ---

func (s *Server) latestSpec(forwardID string) (protocol.ForwardSpec, error) {
	row, err := s.store.LatestForwardSpec(forwardID)
	if err != nil {
		return protocol.ForwardSpec{}, err
	}
	var spec protocol.ForwardSpec
	if err := protocol.DecodeStrictJSONInto([]byte(row.SpecJSON), &spec); err != nil {
		return protocol.ForwardSpec{}, err
	}
	return spec, nil
}

// enqueueDesired queues a full desired snapshot for the node.
func (s *Server) enqueueDesired(nodeID string, desired protocol.DesiredState) error {
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
func (s *Server) buildDesiredState(nodeID, newForwardID string, newSpec protocol.ForwardSpec) (protocol.DesiredState, error) {
	forwards, err := s.store.ListForwards()
	if err != nil {
		return protocol.DesiredState{}, err
	}
	d := protocol.DesiredState{NodeID: nodeID}
	newForwardSeen := false
	for _, f := range forwards {
		if f.NodeID != nodeID {
			continue
		}
		if f.ID == newForwardID {
			d.Forwards = append(d.Forwards, newSpec)
			newForwardSeen = true
			continue
		}
		spec, err := s.latestSpec(f.ID)
		if err != nil {
			return protocol.DesiredState{}, fmt.Errorf("latest spec for forward %q: %w", f.ID, err)
		}
		d.Forwards = append(d.Forwards, spec)
	}
	if newForwardID != "" && !newForwardSeen {
		d.Forwards = append(d.Forwards, newSpec)
	}
	return d, d.Validate()
}

// buildDeleteDesired builds a desired snapshot with the forward ABSENT.
func (s *Server) buildDeleteDesired(nodeID, forwardID, deletionOpID string) (protocol.DesiredState, error) {
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
			// Deletion is a new desired revision, not a rewrite of the
			// latest PRESENT revision. Keeping the same revision would
			// make the Agent reject the changed PRESENT -> ABSENT
			// specification as conflicting intent.
			last.DesiredRevision++
			last.Presence = protocol.PresenceAbsent
			last.DeletionOperationID = deletionOpID
			d.Forwards = append(d.Forwards, last)
			continue
		}
		spec, err := s.latestSpec(f.ID)
		if err != nil {
			return protocol.DesiredState{}, fmt.Errorf("latest spec for forward %q: %w", f.ID, err)
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
		ForwardID: "", Name: strings.TrimSpace(name), Protocol: p, Target: strings.TrimSpace(target), Strategy: st,
		RequestedLocalPort: localPort, RequestedPublicPort: publicPort,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}, nil
}

func validateForwardCreateSpec(spec protocol.ForwardSpec) error {
	if strings.TrimSpace(spec.Name) == "" {
		return errors.New("name is required")
	}
	if spec.Strategy == protocol.StrategyManualStaticV4 && strings.TrimSpace(spec.ManualExpectedEndpoint) == "" {
		return errors.New("manual_expected_endpoint is required for manual-static-v4")
	}
	if spec.PublishScheme != "" && spec.PublishScheme != "http" && spec.PublishScheme != "https" {
		return fmt.Errorf("unknown publish_scheme %q", spec.PublishScheme)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	return nil
}

func specJSON(spec protocol.ForwardSpec) string {
	raw, _ := json.Marshal(spec)
	return string(raw)
}

func desiredJSON(d protocol.DesiredState) string {
	raw, _ := json.Marshal(d)
	return string(raw)
}
