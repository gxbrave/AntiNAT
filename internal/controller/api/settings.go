package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

type settingsView struct {
	ETag               string   `json:"etag"`
	ControllerEndpoint string   `json:"controller_endpoint,omitempty"`
	PrivateSite        bool     `json:"private_site,omitempty"`
	Language           string   `json:"language,omitempty"`
	TCPSTUNServers     []string `json:"tcp_stun_servers,omitempty"`
	UDPSTUNServers     []string `json:"udp_stun_servers,omitempty"`
	ProbeProviderPin   string   `json:"probe_provider_pin,omitempty"`
	ProbeVantage       string   `json:"probe_vantage,omitempty"`
	DetectionScheduler string   `json:"detection_scheduler,omitempty"`
	RetentionDays      int      `json:"retention_days,omitempty"`
	UpdatePolicy       string   `json:"update_policy,omitempty"`
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	record, err := s.store.GetSettingsRecord()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "settings lookup failed")
		return
	}
	var settings settingsView
	if record.JSON != "" && record.JSON != "{}" {
		if err := json.Unmarshal([]byte(record.JSON), &settings); err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "settings are invalid")
			return
		}
	}
	settings.ETag = etagFor(record.Revision)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, settings)
	case http.MethodPut:
		if err := requireIfMatch(w, r, settings.ETag); err != nil {
			return
		}
		var patch settingsView
		if !decodeJSON(w, r, &patch) {
			return
		}
		patch.ETag = ""
		if strings.TrimSpace(patch.Language) != "" && patch.Language != "zh" && patch.Language != "en" {
			writeError(w, 422, "UNPROCESSABLE_ENTITY", "language must be zh or en")
			return
		}
		raw, _ := json.Marshal(patch)
		updated, err := s.store.PutSettingsRecord(record.Revision, string(raw))
		if errors.Is(err, store.ErrCASConflict) {
			writeError(w, 412, "PRECONDITION_FAILED", "settings revision changed")
			return
		}
		if err != nil {
			writeError(w, 500, "INTERNAL_ERROR", "settings update failed")
			return
		}
		patch.ETag = etagFor(updated.Revision)
		writeJSON(w, http.StatusOK, patch)
	default:
		writeError(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "method not allowed")
	}
}
