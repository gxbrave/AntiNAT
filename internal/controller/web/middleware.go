package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// SecurityConfig controls the HTTP security boundary. AllowedOrigins is
// explicit; an empty list permits same-origin requests and requests without an
// Origin header. TrustedProxies controls whether forwarded host/scheme headers
// may be used for same-origin evaluation; an empty list never trusts them.
type SecurityConfig struct {
	AllowedOrigins []string
	TrustedProxies []string
	MaxBodyBytes   int64
}

// SecurityMiddleware adds request IDs, origin/CSRF checks, and a bounded body
// reader. It never logs headers or request bodies, so cookies and payload
// secrets cannot enter application logs through this boundary.
func SecurityMiddleware(next http.Handler, cfg SecurityConfig) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 65536
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		if origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	trustedProxies := make(map[string]struct{}, len(cfg.TrustedProxies))
	for _, proxy := range cfg.TrustedProxies {
		if host := strings.TrimSpace(proxy); host != "" {
			trustedProxies[host] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID()
		w.Header().Set("X-Request-ID", id)
		if isMutation(r.Method) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin != "" {
				_, explicitlyAllowed := allowed[origin]
				if !explicitlyAllowed && !sameOrigin(r, origin, trustedProxies) {
					writeSecurityError(w, http.StatusForbidden, "FORBIDDEN", "request origin is not allowed", id)
					return
				}
			}
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func sameOrigin(r *http.Request, origin string, trustedProxies map[string]struct{}) bool {
	if r == nil || origin == "" {
		return false
	}
	host := r.Host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if peer, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		if _, trusted := trustedProxies[peer]; trusted {
			if forwardedHost := firstForwarded(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
				host = forwardedHost
			}
			if forwardedProto := firstForwarded(r.Header.Get("X-Forwarded-Proto")); forwardedProto == "http" || forwardedProto == "https" {
				scheme = forwardedProto
			}
		}
	}
	return strings.EqualFold(origin, scheme+"://"+host)
}

func firstForwarded(value string) string {
	if idx := strings.IndexByte(value, ','); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func requestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-fallback"
	}
	return hex.EncodeToString(b[:])
}

func writeSecurityError(w http.ResponseWriter, status int, code, message, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}{Code: code, Message: message, RequestID: id})
}
