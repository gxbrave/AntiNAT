package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gxbrave/AntiNAT/internal/controller/deployment"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// deploymentProfileView is the additive P17 deployment-profile projection.
// The profile is deliberately structured and never includes an enrollment
// token or a rendered shell command.
type deploymentProfileView struct {
	NodeID   string             `json:"node_id"`
	Profile  deployment.Profile `json:"profile"`
	Revision uint64             `json:"revision"`
	ETag     string             `json:"etag"`
}

type deploymentProfileRequest struct {
	Profile deployment.Profile `json:"profile"`
}

func (s *Server) handleDeploymentProfile(w http.ResponseWriter, r *http.Request, nodeID string) {
	if strings.TrimSpace(nodeID) == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "node not found")
		return
	}
	if _, err := s.store.GetNode(nodeID); err != nil {
		if errors.Is(err, store.ErrNodeNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "node lookup failed")
		return
	}

	current, err := s.currentDeploymentProfile(nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "deployment profile lookup failed")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, current)
	case http.MethodPut:
		if err := requireIfMatch(w, r, current.ETag); err != nil {
			return
		}
		var body deploymentProfileRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		profile := body.Profile
		if err := profile.ValidateComplete(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", err.Error())
			return
		}
		profile.ControllerEndpoint, err = deployment.NormalizeOptionalServiceURL(profile.ControllerEndpoint)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "invalid controller endpoint")
			return
		}
		if profile.GitHubProxy != "" {
			profile.GitHubProxy, err = deployment.NormalizeOptionalServiceURL(profile.GitHubProxy)
			if err != nil {
				writeError(w, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "invalid github proxy")
				return
			}
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "deployment profile encoding failed")
			return
		}
		updated, err := s.store.PutDeploymentProfile(nodeID, current.Revision, string(raw))
		if errors.Is(err, store.ErrCASConflict) {
			writeError(w, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "deployment profile revision changed")
			return
		}
		if errors.Is(err, store.ErrNodeNotFound) || errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "node not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "deployment profile update failed")
			return
		}
		writeJSON(w, http.StatusOK, deploymentProfileView{NodeID: nodeID, Profile: profile, Revision: updated.Revision, ETag: etagFor(updated.Revision)})
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}

func (s *Server) currentDeploymentProfile(nodeID string) (deploymentProfileView, error) {
	rec, err := s.store.GetDeploymentProfile(nodeID)
	if errors.Is(err, store.ErrNotFound) {
		profile := deployment.DefaultProfile(s.settingsControllerEndpoint())
		return deploymentProfileView{NodeID: nodeID, Profile: profile, Revision: 0, ETag: etagFor(0)}, nil
	}
	if err != nil {
		return deploymentProfileView{}, err
	}
	profile, err := deployment.DecodeProfileJSON([]byte(rec.JSON))
	if err != nil {
		return deploymentProfileView{}, err
	}
	return deploymentProfileView{NodeID: nodeID, Profile: profile, Revision: rec.Revision, ETag: etagFor(rec.Revision)}, nil
}

func (s *Server) settingsControllerEndpoint() string {
	rec, err := s.store.GetSettingsRecord()
	if err != nil || rec.JSON == "" {
		return ""
	}
	var settings struct {
		ControllerEndpoint string `json:"controller_endpoint"`
	}
	if json.Unmarshal([]byte(rec.JSON), &settings) != nil {
		return ""
	}
	return strings.TrimSpace(settings.ControllerEndpoint)
}
