package api

import (
	"net/http"
	"time"
)

// readyFunc reports a component's readiness; a nil function means ready.
type readiness struct {
	storeOK bool
	authOK  bool
}

// healthState is the shared liveness/readiness state (Story 5 wires it).
type healthState struct {
	mu      chan bool // unused; kept simple
	storeOK bool
	authOK  bool
	started time.Time
}

func newHealthState() *healthState {
	return &healthState{started: time.Now()}
}

func (h *healthState) setStoreReady(ok bool) { h.storeOK = ok }
func (h *healthState) setAuthReady(ok bool)  { h.authOK = ok }

// handleHealthz implements GET /healthz: liveness only.
func (h *healthState) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz implements GET /readyz: 503 until every component is ready.
func (h *healthState) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ready := h.storeOK && h.authOK
	status := http.StatusOK
	code := "ok"
	if !ready {
		status = http.StatusServiceUnavailable
		code = "not_ready"
	}
	writeJSON(w, status, map[string]any{
		"status":     code,
		"readiness":  map[string]string{"store": boolStr(h.storeOK), "auth": boolStr(h.authOK)},
		"uptime_sec": int64(time.Since(h.started).Seconds()),
	})
}

func boolStr(b bool) string {
	if b {
		return "ready"
	}
	return "not_ready"
}
