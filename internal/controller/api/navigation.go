package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

type navigationCategoryView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	OrderIndex int    `json:"order_index"`
	ETag       string `json:"etag"`
}

type navigationItemView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	CategoryID  string `json:"category_id"`
	ForwardID   string `json:"forward_id"`
	OrderIndex  int    `json:"order_index"`
	ETag        string `json:"etag"`
}

func navigationCategoryProjection(c store.NavigationCategory) navigationCategoryView {
	return navigationCategoryView{ID: c.ID, Name: c.Name, OrderIndex: c.OrderIndex, ETag: etagFor(c.Revision)}
}

func navigationItemProjection(i store.NavigationItem) navigationItemView {
	return navigationItemView{ID: i.ID, Name: i.Name, Description: i.Description, Protocol: i.Protocol, CategoryID: i.CategoryID, ForwardID: i.ForwardID, OrderIndex: i.OrderIndex, ETag: etagFor(i.Revision)}
}

func (s *Server) handleNavigation(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(r.URL.Path, "/api/v1/navigation/"))
	switch {
	case len(parts) == 1 && parts[0] == "categories":
		s.handleCategories(w, r)
	case len(parts) == 2 && parts[0] == "categories":
		s.handleCategory(w, r, parts[1])
	case len(parts) == 1 && parts[0] == "items":
		s.handleItems(w, r)
	case len(parts) == 2 && parts[0] == "items":
		s.handleItem(w, r, parts[1])
	case len(parts) == 1 && parts[0] == "order":
		s.handleNavigationOrder(w, r)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "navigation route not found")
	}
}

func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.store.ListNavigationCategories()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list categories failed")
			return
		}
		out := make([]navigationCategoryView, 0, len(rows))
		for _, row := range rows {
			out = append(out, navigationCategoryProjection(row))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		principal := "admin"
		if user, ok := s.currentUser(r); ok && user.ID != "" {
			principal = user.ID
		}
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			Name       string `json:"name"`
			OrderIndex int    `json:"order_index"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if strings.TrimSpace(body.Name) == "" {
			writeError(w, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "name is required")
			return
		}
		id, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		// repair-1 H4: durable idempotency (replay/conflict) is decided inside
		// the same BEGIN IMMEDIATE transaction as the insert, so the API does
		// more than validate the key format.
		projected := navigationCategoryProjection(store.NavigationCategory{ID: id, Name: body.Name, OrderIndex: body.OrderIndex, Revision: 1})
		raw, _ := json.Marshal(projected)
		rec, replayed, err := s.store.CreateNavigationCategoryIdempotent(r.Context(), store.NavigationCategory{ID: id, Name: body.Name, OrderIndex: body.OrderIndex}, store.IdempotencyRecord{
			Key: key, Route: "/api/v1/navigation/categories", Principal: principal,
			RequestHash: requestHashOf(body), ResponseStatus: http.StatusCreated, ResponseBody: string(raw),
		})
		if errors.Is(err, store.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
			return
		}
		if errors.Is(err, store.ErrNavigationOrderConflict) {
			writeError(w, http.StatusConflict, "CONFLICT", "category order conflicts")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "category create failed")
			return
		}
		if replayed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.ResponseStatus)
			_, _ = w.Write([]byte(rec.ResponseBody))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(raw)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

func (s *Server) handleCategory(w http.ResponseWriter, r *http.Request, id string) {
	row, err := s.store.GetNavigationCategory(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "category not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "category lookup failed")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if err := requireIfMatch(w, r, etagFor(row.Revision)); err != nil {
			return
		}
		var body struct {
			Name       *string `json:"name"`
			OrderIndex *int    `json:"order_index"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name != nil {
			row.Name = *body.Name
		}
		if body.OrderIndex != nil {
			row.OrderIndex = *body.OrderIndex
		}
		updated, err := s.store.UpdateNavigationCategoryCAS(row.ID, row.Revision, row.Name, row.OrderIndex)
		if errors.Is(err, store.ErrNavigationOrderConflict) {
			writeError(w, http.StatusConflict, "CONFLICT", "category order conflicts")
			return
		}
		if errors.Is(err, store.ErrCASConflict) {
			writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "category revision changed")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "category update failed")
			return
		}
		writeJSON(w, http.StatusOK, navigationCategoryProjection(updated))
	case http.MethodDelete:
		if err := requireIfMatch(w, r, etagFor(row.Revision)); err != nil {
			return
		}
		if err := s.store.DeleteNavigationCategoryCAS(row.ID, row.Revision); errors.Is(err, store.ErrCASConflict) {
			writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "category revision changed")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "category delete failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

func (s *Server) handleItems(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.store.ListNavigationItems()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "list items failed")
			return
		}
		out := make([]navigationItemView, 0, len(rows))
		for _, row := range rows {
			out = append(out, navigationItemProjection(row))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		principal := "admin"
		if user, ok := s.currentUser(r); ok && user.ID != "" {
			principal = user.ID
		}
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Idempotency-Key is required (8..128 chars)")
			return
		}
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			CategoryID  string `json:"category_id"`
			ForwardID   string `json:"forward_id"`
			OrderIndex  int    `json:"order_index"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if strings.TrimSpace(body.Name) == "" || body.CategoryID == "" || body.ForwardID == "" {
			writeError(w, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "name, category_id and forward_id are required")
			return
		}
		fwd, err := s.store.GetForward(body.ForwardID)
		if errors.Is(err, store.ErrForwardNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "forward not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "forward lookup failed")
			return
		}
		id, err := randomHexID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "id generation failed")
			return
		}
		// repair-1 H4: durable idempotency (replay/conflict) is decided
		// atomically with the insert.
		projected := navigationItemProjection(store.NavigationItem{ID: id, Name: body.Name, Description: body.Description, Protocol: fwd.Protocol, CategoryID: body.CategoryID, ForwardID: body.ForwardID, OrderIndex: body.OrderIndex, Revision: 1})
		raw, _ := json.Marshal(projected)
		rec, replayed, err := s.store.CreateNavigationItemIdempotent(r.Context(), store.NavigationItem{ID: id, Name: body.Name, Description: body.Description, Protocol: fwd.Protocol, CategoryID: body.CategoryID, ForwardID: body.ForwardID, OrderIndex: body.OrderIndex}, store.IdempotencyRecord{
			Key: key, Route: "/api/v1/navigation/items", Principal: principal,
			RequestHash: requestHashOf(body), ResponseStatus: http.StatusCreated, ResponseBody: string(raw),
		})
		if errors.Is(err, store.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key reused with a different request")
			return
		}
		if errors.Is(err, store.ErrNavigationOrderConflict) {
			writeError(w, http.StatusConflict, "CONFLICT", "navigation item relation or order conflicts")
			return
		}
		if errors.Is(err, store.ErrForwardNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "forward not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "item create failed")
			return
		}
		if replayed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.ResponseStatus)
			_, _ = w.Write([]byte(rec.ResponseBody))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(raw)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

func (s *Server) handleItem(w http.ResponseWriter, r *http.Request, id string) {
	row, err := s.store.GetNavigationItem(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "navigation item not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "navigation item lookup failed")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if err := requireIfMatch(w, r, etagFor(row.Revision)); err != nil {
			return
		}
		var body struct {
			Name        *string `json:"name"`
			Description *string `json:"description"`
			CategoryID  *string `json:"category_id"`
			ForwardID   *string `json:"forward_id"`
			OrderIndex  *int    `json:"order_index"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name != nil {
			row.Name = *body.Name
		}
		if body.Description != nil {
			row.Description = *body.Description
		}
		if body.CategoryID != nil {
			row.CategoryID = *body.CategoryID
		}
		if body.ForwardID != nil {
			row.ForwardID = *body.ForwardID
		}
		if body.OrderIndex != nil {
			row.OrderIndex = *body.OrderIndex
		}
		updated, err := s.store.UpdateNavigationItemCAS(row, row.Revision)
		if errors.Is(err, store.ErrNavigationOrderConflict) {
			writeError(w, http.StatusConflict, "CONFLICT", "navigation item conflict")
			return
		}
		if errors.Is(err, store.ErrCASConflict) {
			writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "item revision changed")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "item update failed")
			return
		}
		writeJSON(w, http.StatusOK, navigationItemProjection(updated))
	case http.MethodDelete:
		if err := requireIfMatch(w, r, etagFor(row.Revision)); err != nil {
			return
		}
		if err := s.store.DeleteNavigationItemCAS(row.ID, row.Revision); errors.Is(err, store.ErrCASConflict) {
			writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "item revision changed")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "item delete failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

func (s *Server) handleNavigationOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
		return
	}
	order, err := s.store.GetNavigationOrder()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "navigation order lookup failed")
		return
	}
	if err := requireIfMatch(w, r, etagFor(order.Revision)); err != nil {
		return
	}
	var body struct {
		CategoryIDs []string `json:"category_ids"`
		ItemIDs     []string `json:"item_ids"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	updated, err := s.store.PutNavigationOrder(order.Revision, store.NavigationOrder{CategoryIDs: body.CategoryIDs, ItemIDs: body.ItemIDs})
	if errors.Is(err, store.ErrCASConflict) {
		writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "navigation order changed")
		return
	}
	if errors.Is(err, store.ErrNavigationOrderConflict) {
		writeError(w, http.StatusConflict, "CONFLICT", "navigation order conflict")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "navigation order update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"category_ids": updated.CategoryIDs, "item_ids": updated.ItemIDs})
}

func validIdempotencyKey(r *http.Request) bool {
	key := r.Header.Get("Idempotency-Key")
	return len(key) >= 8 && len(key) <= 128
}

// Keep json imported in older generated fixtures that use this package's
// helper through go:linkname-free builds.
var _ = strings.TrimSpace
