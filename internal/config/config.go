// Package config parses and validates the Controller and Agent
// configuration files.
//
// Format: strict JSON (single object, no duplicate keys, no unknown fields,
// bounded nesting and numbers). Safe defaults are applied before
// validation, and validation FAILS CLOSED: a Controller without an
// enrollment token source never starts with public enrollment, and a token
// file must have mode exactly 0600. Secret material (token contents) is
// never stored in or logged from config; only the token file path is kept,
// and Redacted() removes even that from loggable output.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// Frozen Linux config paths (docs/installer-contract.md §3).
const (
	DefaultControllerConfigPath = "/etc/antinat/controller.conf"
	DefaultAgentConfigPath      = "/etc/antinat/agent.conf"
)

// Defaults.
const (
	defaultListenAddress = ":3111"
	defaultDataDir       = "/var/lib/antinat"
	defaultLogLevel      = "info"
	defaultControllerDB  = "controller.db"
	defaultAgentDB       = "agent.db"
	defaultKeyDir        = "keys"
)

// Stable configuration rejection reasons.
var (
	ErrEnrollmentRequired   = errors.New("config: controller requires an enrollment token source; public enrollment is not permitted")
	ErrInvalidListenAddress = errors.New("config: invalid listen address")
	ErrInvalidURL           = errors.New("config: invalid URL")
	ErrInvalidPort          = errors.New("config: port out of range 1..65535")
	ErrTokenFilePermissions = errors.New("config: token file must have mode exactly 0600")
	ErrInvalidLogLevel      = errors.New("config: unknown log level")
	ErrDuplicateKey         = errors.New("config: duplicate JSON key")
	ErrUnknownField         = errors.New("config: unknown config field")
	ErrInvalidCapability    = errors.New("config: invalid capability")
)

var validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

// ---------------------------------------------------------------------------
// strict JSON config decoding
// ---------------------------------------------------------------------------

// decodeStrict enforces the frozen strict JSON rules and rejects unknown
// fields against the target struct.
func decodeStrict(data []byte, v any) error {
	if err := protocol.ValidateStrictJSON(data, nil); err != nil {
		return fmt.Errorf("config: strict json: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("config: trailing content after config object")
	}
	return nil
}

func validateLogLevel(level string) error {
	if !validLogLevels[level] {
		return fmt.Errorf("%w: %q", ErrInvalidLogLevel, level)
	}
	return nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: %d", ErrInvalidPort, port)
	}
	return nil
}

// normalizeListenAddress validates a listen address of the form host:port.
func normalizeListenAddress(addr string) error {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidListenAddress, addr)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidListenAddress, addr)
	}
	return validatePort(port)
}

// normalizeHTTPSURL validates an absolute http(s) URL with a non-empty host.
func normalizeHTTPSURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidURL, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%w: scheme %q must be http or https", ErrInvalidURL, u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidURL)
	}
	if h := u.Hostname(); h == "" {
		return "", fmt.Errorf("%w: empty hostname", ErrInvalidURL)
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrInvalidURL, raw)
		}
		if err := validatePort(port); err != nil {
			return "", err
		}
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: userinfo is not permitted", ErrInvalidURL)
	}
	return u.String(), nil
}

// normalizeControllerEndpoint applies the default control port when the URL
// omits one: 3111 for http (AntiNAT default), 443 for https.
func normalizeControllerEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidURL, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%w: scheme %q must be http or https", ErrInvalidURL, u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%w: empty hostname", ErrInvalidURL)
	}
	if u.Port() == "" {
		port := "3111"
		if u.Scheme == "https" {
			port = "443"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	} else {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrInvalidURL, raw)
		}
		if err := validatePort(port); err != nil {
			return "", err
		}
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: userinfo is not permitted", ErrInvalidURL)
	}
	return u.String(), nil
}

// validateStunURL requires one of the explicit AntiNAT STUN config formats
// (v0.8 §11.4): stun://, stun+udp://, or stun+tcp://.
func validateStunURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidURL, raw)
	}
	switch u.Scheme {
	case "stun", "stun+udp", "stun+tcp":
	default:
		return fmt.Errorf("%w: stun URL scheme %q must be stun, stun+udp, or stun+tcp", ErrInvalidURL, u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: stun URL has no host", ErrInvalidURL)
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return fmt.Errorf("%w: %q", ErrInvalidURL, raw)
		}
		if err := validatePort(port); err != nil {
			return err
		}
	}
	return nil
}

// checkTokenFileMode fails closed unless the token file is mode 0600.
func checkTokenFileMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: stat token file %s: %w", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: %s has mode %v", ErrTokenFilePermissions, path, info.Mode().Perm())
	}
	return nil
}

// ---------------------------------------------------------------------------
// ControllerConfig
// ---------------------------------------------------------------------------

// TLSConfig controls an optional controller TLS listener.
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

// RateLimitConfig bounds per-principal API rate limiting.
type RateLimitConfig struct {
	Enabled           bool `json:"enabled"`
	RequestsPerMinute int  `json:"requests_per_minute"`
}

// ControllerConfig is the Controller configuration.
type ControllerConfig struct {
	ListenAddress       string          `json:"listen_address"`
	DataDir             string          `json:"data_dir"`
	DatabasePath        string          `json:"database_path"`
	LogLevel            string          `json:"log_level"`
	EnrollmentTokenFile string          `json:"enrollment_token_file"`
	PublicURL           string          `json:"public_url,omitempty"`
	TLS                 TLSConfig       `json:"tls"`
	RateLimit           RateLimitConfig `json:"rate_limit"`
}

// ParseControllerConfig parses and validates a Controller config, applying
// safe defaults and failing closed on an insecure enrollment default.
func ParseControllerConfig(data []byte) (*ControllerConfig, error) {
	cfg := &ControllerConfig{}
	if err := decodeStrict(data, cfg); err != nil {
		return nil, err
	}
	applyControllerDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyControllerDefaults(cfg *ControllerConfig) {
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = defaultListenAddress
	}
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = filepath.Join(cfg.DataDir, defaultControllerDB)
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
	}
}

// Validate enforces the Controller invariants (fail closed).
func (c *ControllerConfig) Validate() error {
	if c.EnrollmentTokenFile == "" {
		return ErrEnrollmentRequired
	}
	if err := normalizeListenAddress(c.ListenAddress); err != nil {
		return err
	}
	if err := validateLogLevel(c.LogLevel); err != nil {
		return err
	}
	if c.PublicURL != "" {
		if _, err := normalizeHTTPSURL(c.PublicURL); err != nil {
			return err
		}
	}
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New("config: tls.enabled requires cert_file and key_file")
		}
	}
	if c.RateLimit.Enabled && c.RateLimit.RequestsPerMinute < 1 {
		return errors.New("config: rate_limit.requests_per_minute must be >= 1 when enabled")
	}
	return nil
}

// Redacted returns a copy safe for logging: token file paths are removed.
func (c *ControllerConfig) Redacted() *ControllerConfig {
	out := *c
	if out.EnrollmentTokenFile != "" {
		out.EnrollmentTokenFile = "[REDACTED]"
	}
	return &out
}

// String renders a loggable (redacted) representation.
func (c *ControllerConfig) String() string {
	return fmt.Sprintf("ControllerConfig{listen=%s data_dir=%s db=%s log=%s enrollment_token_file=%s public_url=%s tls=%v rate_limit=%v}",
		c.ListenAddress, c.DataDir, c.DatabasePath, c.LogLevel,
		redactPath(c.EnrollmentTokenFile), c.PublicURL, c.TLS.Enabled, c.RateLimit.Enabled)
}

// LoadControllerConfig reads and validates a Controller config file,
// enforcing 0600 on the enrollment token file.
func LoadControllerConfig(path string) (*ControllerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := ParseControllerConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkTokenFileMode(cfg.EnrollmentTokenFile); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// AgentConfig
// ---------------------------------------------------------------------------

// AgentConfig is the Agent configuration.
type AgentConfig struct {
	ControllerEndpoint string          `json:"controller_endpoint"`
	DataDir            string          `json:"data_dir"`
	BoltPath           string          `json:"bolt_path"`
	KeyDir             string          `json:"key_dir"`
	TokenFile          string          `json:"token_file"`
	BindInterface      string          `json:"bind_interface"`
	DedicatedUID       int             `json:"dedicated_uid"`
	DedicatedGID       int             `json:"dedicated_gid"`
	LogLevel           string          `json:"log_level"`
	StunServers        []string        `json:"stun_servers"`
	Capabilities       map[string]bool `json:"capabilities"`
}

// ParseAgentConfig parses and validates an Agent config with safe defaults.
func ParseAgentConfig(data []byte) (*AgentConfig, error) {
	cfg := &AgentConfig{}
	if err := decodeStrict(data, cfg); err != nil {
		return nil, err
	}
	applyAgentDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyAgentDefaults(cfg *AgentConfig) {
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir
	}
	if cfg.BoltPath == "" {
		cfg.BoltPath = filepath.Join(cfg.DataDir, defaultAgentDB)
	}
	if cfg.KeyDir == "" {
		cfg.KeyDir = filepath.Join(cfg.DataDir, defaultKeyDir)
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
	}
	if cfg.ControllerEndpoint != "" {
		// normalizeControllerEndpoint applies the default control port.
		if norm, err := normalizeControllerEndpoint(cfg.ControllerEndpoint); err == nil {
			cfg.ControllerEndpoint = norm
		}
	}
}

// Validate enforces the Agent invariants.
func (c *AgentConfig) Validate() error {
	if c.ControllerEndpoint == "" {
		return errors.New("config: agent requires controller_endpoint")
	}
	norm, err := normalizeControllerEndpoint(c.ControllerEndpoint)
	if err != nil {
		return err
	}
	c.ControllerEndpoint = norm
	if err := validateLogLevel(c.LogLevel); err != nil {
		return err
	}
	if c.DedicatedUID < 0 {
		return errors.New("config: dedicated_uid must be >= 0")
	}
	if c.DedicatedGID < 0 {
		return errors.New("config: dedicated_gid must be >= 0")
	}
	for _, s := range c.StunServers {
		if err := validateStunURL(s); err != nil {
			return err
		}
	}
	return nil
}

// Redacted returns a copy safe for logging: token paths are removed.
func (c *AgentConfig) Redacted() *AgentConfig {
	out := *c
	if out.TokenFile != "" {
		out.TokenFile = "[REDACTED]"
	}
	return &out
}

// String renders a loggable (redacted) representation.
func (c *AgentConfig) String() string {
	return fmt.Sprintf("AgentConfig{endpoint=%s data_dir=%s bolt=%s keys=%s token_file=%s interface=%s uid=%d gid=%d log=%s stun=%d caps=%d}",
		c.ControllerEndpoint, c.DataDir, c.BoltPath, c.KeyDir,
		redactPath(c.TokenFile), c.BindInterface, c.DedicatedUID, c.DedicatedGID,
		c.LogLevel, len(c.StunServers), len(c.Capabilities))
}

// redactPath never renders sensitive token paths in log output.
func redactPath(path string) string {
	if path == "" {
		return ""
	}
	return "[REDACTED]"
}

// LoadAgentConfig reads and validates an Agent config file, enforcing 0600 on
// the token file.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := ParseAgentConfig(data)
	if err != nil {
		return nil, err
	}
	if cfg.TokenFile != "" {
		if err := checkTokenFileMode(cfg.TokenFile); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}
