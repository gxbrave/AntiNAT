package agenthub

import "net/http"

// handleControl is the WebSocket control endpoint (Story 3). Until the
// session implementation lands it fails closed.
func (h *Hub) handleControl(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "control channel not available", http.StatusServiceUnavailable)
}
