package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/hook"
)

// Hook handlers (P16). Implements the frozen openapi hook surface: webhook
// definitions CRUD, hook-secret metadata CRUD (values never returned), and
// delivery retry. Every mutation uses ETag/If-Match (428 missing, 412 stale);
// creates carry a durable Idempotency-Key (409 on conflict).

// hookDefinitionView is the API-facing HookDefinition (openapi).
type hookDefinitionView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	URL  string `json:"url"`
	ETag string `json:"etag"`
}

func (s *Server) hookDefinitionView(d hook.Definition) hookDefinitionView {
	return hookDefinitionView{ID: d.ID, Name: d.Name, Kind: d.Kind, URL: d.URL, ETag: etagFor(d.Revision)}
}

// hookSecretView is the API-facing HookSecret metadata (openapi); the secret
// value is never part of any response.
type hookSecretView struct {
	ID        string `json:"id"`
	SecretID  string `json:"secret_id"`
	Algorithm string `json:"algorithm"`
	ETag      string `json:"etag"`
}

func (s *Server) hookSecretView(sc hook.Secret) hookSecretView {
	return hookSecretView{ID: sc.ID, SecretID: sc.SecretID, Algorithm: sc.Algorithm, ETag: etagFor(sc.Revision)}
}

// handleHookDefinitions implements GET/POST /api/v1/hooks/definitions.
func (s *Server) handleHookDefinitions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		defs, err := s.hooks.ListDefinitions()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list hook definitions failed")
			return
		}
		items := make([]hookDefinitionView, 0, len(defs))
		for _, d := range defs {
			items = append(items, s.hookDefinitionView(d))
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			URL  string `json:"url"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		s.idempotencyMu.Lock()
		defer s.idempotencyMu.Unlock()
		principal := idempotencyPrincipal(s, r)
		requestHash := requestHashOf(body)
		if existing, err := s.store.GetIdempotency(key); err == nil && existing.ExpiresAt > time.Now().Unix() {
			if existing.Route != "/api/v1/hooks/definitions" || existing.Principal != principal || existing.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
				return
			}
			if existing.ResponseBody == "" {
				writeError(w, http.StatusConflict, "CONFLICT", "request with this Idempotency-Key is in progress")
				return
			}
			writeRaw(w, existing.ResponseStatus, existing.ResponseBody)
			return
		}
		d, err := s.hooks.CreateDefinition(body.Name, body.Kind, body.URL)
		if err != nil {
			writeHookValidationError(w, err)
			return
		}
		view := s.hookDefinitionView(d)
		raw, _ := json.Marshal(view)
		if _, replayed, err := s.store.StoreIdempotency(store.IdempotencyRecord{
			Key: key, Route: "/api/v1/hooks/definitions", Principal: principal,
			RequestHash: requestHash, ResponseStatus: http.StatusCreated, ResponseBody: string(raw),
		}); err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "idempotency record failed")
			return
		} else if replayed {
			writeRaw(w, http.StatusCreated, string(raw))
			return
		}
		writeRaw(w, http.StatusCreated, string(raw))
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// handleHookDefinitionByID implements PATCH/DELETE /api/v1/hooks/definitions/{id}.
func (s *Server) handleHookDefinitionByID(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path[len("/api/v1/hooks/definitions/"):])
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown hook definition route")
		return
	}
	id := parts[0]
	if r.Method == http.MethodPatch || r.Method == http.MethodDelete {
		if r.Header.Get("If-Match") == "" {
			writeError(w, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "If-Match is required")
			return
		}
	}
	current, err := s.hooks.Store.GetDefinition(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "hook definition not found")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if err := requireIfMatch(w, r, etagFor(current.Revision)); err != nil {
			return
		}
		var body struct {
			Name *string `json:"name"`
			URL  *string `json:"url"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name == nil && body.URL == nil {
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "at least one supported field is required")
			return
		}
		updated, err := s.hooks.UpdateDefinition(id, body.Name, body.URL, current.Revision)
		if err != nil {
			writeHookValidationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, s.hookDefinitionView(updated))
	case http.MethodDelete:
		if err := requireIfMatch(w, r, etagFor(current.Revision)); err != nil {
			return
		}
		if err := s.hooks.DeleteDefinition(id, current.Revision); err != nil {
			if errors.Is(err, hook.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "hook definition not found")
				return
			}
			if errors.Is(err, hook.ErrCASConflict) {
				writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "ETag mismatch")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "delete hook definition failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// handleHookSecrets implements GET/POST /api/v1/hooks/secrets.
func (s *Server) handleHookSecrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		secrets, err := s.hooks.ListSecrets()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list hook secrets failed")
			return
		}
		items := make([]hookSecretView, 0, len(secrets))
		for _, sc := range secrets {
			items = append(items, s.hookSecretView(sc))
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			SecretID  string `json:"secret_id"`
			Algorithm string `json:"algorithm"`
			Value     string `json:"value"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		s.idempotencyMu.Lock()
		defer s.idempotencyMu.Unlock()
		principal := idempotencyPrincipal(s, r)
		requestHash := requestHashOf(body)
		if existing, err := s.store.GetIdempotency(key); err == nil && existing.ExpiresAt > time.Now().Unix() {
			if existing.Route != "/api/v1/hooks/secrets" || existing.Principal != principal || existing.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
				return
			}
			if existing.ResponseBody == "" {
				writeError(w, http.StatusConflict, "CONFLICT", "request with this Idempotency-Key is in progress")
				return
			}
			writeRaw(w, existing.ResponseStatus, existing.ResponseBody)
			return
		}
		sc, err := s.hooks.CreateSecret(body.SecretID, body.Algorithm, body.Value)
		if err != nil {
			if errors.Is(err, hook.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "a hook secret with this secret_id already exists")
				return
			}
			writeHookValidationError(w, err)
			return
		}
		view := s.hookSecretView(sc)
		raw, _ := json.Marshal(view)
		if _, replayed, err := s.store.StoreIdempotency(store.IdempotencyRecord{
			Key: key, Route: "/api/v1/hooks/secrets", Principal: principal,
			RequestHash: requestHash, ResponseStatus: http.StatusCreated, ResponseBody: string(raw),
		}); err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "idempotency record failed")
			return
		} else if replayed {
			writeRaw(w, http.StatusCreated, string(raw))
			return
		}
		writeRaw(w, http.StatusCreated, string(raw))
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

// handleHookSecretByID implements DELETE /api/v1/hooks/secrets/{id}.
func (s *Server) handleHookSecretByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
	if r.Header.Get("If-Match") == "" {
		writeError(w, http.StatusPreconditionRequired, "PRECONDITION_REQUIRED", "If-Match is required")
		return
	}
	parts := splitPath(r.URL.Path[len("/api/v1/hooks/secrets/"):])
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown hook secret route")
		return
	}
	id := parts[0]
	current, err := s.hooks.Store.GetSecretByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "hook secret not found")
		return
	}
	if err := requireIfMatch(w, r, etagFor(current.Revision)); err != nil {
		return
	}
	if err := s.hooks.DeleteSecret(id, current.Revision); err != nil {
		if errors.Is(err, hook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "hook secret not found")
			return
		}
		if errors.Is(err, hook.ErrCASConflict) {
			writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "ETag mismatch")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "delete hook secret failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleHookDeliveryRoute implements POST /api/v1/hook-deliveries/{id}/retry.
func (s *Server) handleHookDeliveryRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
	rest := splitPath(r.URL.Path[len("/api/v1/hook-deliveries/"):])
	if len(rest) != 2 || rest[1] != "retry" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown hook delivery route")
		return
	}
	delivery, err := s.hooks.Store.GetDelivery(rest[0])
	if err != nil {
		if errors.Is(err, hook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "hook delivery not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "hook delivery lookup failed")
		return
	}
	opID, err := randomHexID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "operation id generation failed")
		return
	}
	retried, err := s.hooks.RetryDelivery(delivery.ID)
	if err != nil {
		if errors.Is(err, hook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "hook delivery not found")
			return
		}
		if errors.Is(err, hook.ErrInvalid) {
			writeError(w, http.StatusConflict, "CONFLICT", "delivery is not retryable from its current state")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "retry hook delivery failed")
		return
	}
	stored, err := s.store.CreateAPIOperation(store.APIOperation{
		ID: opID, Kind: "hook_delivery_retry", NodeID: retried.NodeID,
		State: "ACCEPTED", Detail: "delivery " + retried.ID + " requeued",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "operation record failed")
		return
	}
	writeJSON(w, http.StatusAccepted, apiOperationView(stored))
}

// apiOperationView renders the frozen Operation schema for a stored operation.
func apiOperationView(op store.APIOperation) operationView {
	return operationView{
		OperationID: op.ID, State: op.State, Detail: op.Detail,
		RemoteCleanupConfirmed: op.RemoteCleanupConfirmed,
		CreatedAt:              operationTime(op.CreatedAt),
		UpdatedAt:              operationTime(maxInt64(op.CreatedAt, op.CompletedAt)),
	}
}

func writeHookValidationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hook.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, hook.ErrCASConflict):
		writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "ETag mismatch")
	case errors.Is(err, hook.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", "hook record not found")
	default:
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "hook operation failed")
	}
}

func writeRaw(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func idempotencyPrincipal(s *Server, r *http.Request) string {
	if user, ok := s.currentUser(r); ok && user.ID != "" {
		return user.ID
	}
	return "admin"
}
