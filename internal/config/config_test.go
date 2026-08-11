package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Story 5 RED: unknown keys, an insecure public-enrollment default,
// malformed URLs, and out-of-bounds values must all fail; safe defaults must
// apply; secrets must never be logged.

func TestControllerDefaults(t *testing.T) {
	// The default configuration must FAIL CLOSED: a Controller without an
	// enrollment token source must not start with public enrollment.
	if _, err := ParseControllerConfig([]byte(`{}`)); err == nil {
		t.Fatal("default controller config accepted (insecure public enrollment default)")
	}
	// With an enrollment token source, safe defaults apply.
	cfg, err := ParseControllerConfig([]byte(`{"enrollment_token_file":"/etc/antinat/enroll.token"}`))
	if err != nil {
		t.Fatalf("valid controller config rejected: %v", err)
	}
	if cfg.ListenAddress != ":3111" {
		t.Errorf("default listen_address=%q want :3111", cfg.ListenAddress)
	}
	if cfg.DataDir != "/var/lib/antinat" {
		t.Errorf("default data_dir=%q", cfg.DataDir)
	}
	if cfg.DatabasePath != "/var/lib/antinat/controller.db" {
		t.Errorf("default database_path=%q", cfg.DatabasePath)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("default log_level=%q", cfg.LogLevel)
	}
	if cfg.EnrollmentTokenFile != "/etc/antinat/enroll.token" {
		t.Errorf("enrollment_token_file=%q", cfg.EnrollmentTokenFile)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validated config rejected: %v", err)
	}
}

func TestControllerRejectsUnknownKeys(t *testing.T) {
	raw := `{"enrollment_token_file":"/etc/antinat/t","public_enrollment":true}`
	if _, err := ParseControllerConfig([]byte(raw)); err == nil {
		t.Fatal("unknown key public_enrollment accepted")
	}
	if _, err := ParseControllerConfig([]byte(`{"enrollment_token_file":"/etc/antinat/t","zzz":1}`)); err == nil {
		t.Fatal("unknown key zzz accepted")
	}
}

func TestControllerRejectsMalformedFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"bad-listen-address", `{"enrollment_token_file":"/etc/antinat/t","listen_address":"not-an-address"}`},
		{"listen-port-overflow", `{"enrollment_token_file":"/etc/antinat/t","listen_address":"0.0.0.0:65536"}`},
		{"listen-port-zero", `{"enrollment_token_file":"/etc/antinat/t","listen_address":"0.0.0.0:0"}`},
		{"bad-public-url", `{"enrollment_token_file":"/etc/antinat/t","public_url":"ftp://x"}`},
		{"bad-log-level", `{"enrollment_token_file":"/etc/antinat/t","log_level":"loud"}`},
		{"rate-limit-zero", `{"enrollment_token_file":"/etc/antinat/t","rate_limit":{"enabled":true,"requests_per_minute":0}}`},
		{"tls-enabled-no-files", `{"enrollment_token_file":"/etc/antinat/t","tls":{"enabled":true}}`},
		{"tls-cert-only", `{"enrollment_token_file":"/etc/antinat/t","tls":{"enabled":true,"cert_file":"/c.pem"}}`},
		{"duplicate-key", `{"enrollment_token_file":"/etc/antinat/t","enrollment_token_file":"/other"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseControllerConfig([]byte(tc.raw)); err == nil {
				t.Fatalf("malformed controller config accepted: %s", tc.name)
			}
		})
	}
}

func TestControllerExplicitListen(t *testing.T) {
	cfg, err := ParseControllerConfig([]byte(`{"enrollment_token_file":"/t","listen_address":"127.0.0.1:9000"}`))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.ListenAddress != "127.0.0.1:9000" {
		t.Fatalf("listen_address=%q", cfg.ListenAddress)
	}
}

func TestAgentConfig(t *testing.T) {
	cfg, err := ParseAgentConfig([]byte(`{"controller_endpoint":"https://ctl.example.com:3111","token_file":"/var/lib/antinat/enroll.token"}`))
	if err != nil {
		t.Fatalf("valid agent config rejected: %v", err)
	}
	if cfg.ControllerEndpoint != "https://ctl.example.com:3111" {
		t.Errorf("controller_endpoint=%q", cfg.ControllerEndpoint)
	}
	if cfg.DataDir != "/var/lib/antinat" {
		t.Errorf("default data_dir=%q", cfg.DataDir)
	}
	if cfg.BoltPath != "/var/lib/antinat/agent.db" {
		t.Errorf("default bolt_path=%q", cfg.BoltPath)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validated agent config rejected: %v", err)
	}
}

func TestAgentRejectsUnknownKeys(t *testing.T) {
	if _, err := ParseAgentConfig([]byte(`{"controller_endpoint":"https://x:3111","zzz":1}`)); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := ParseAgentConfig([]byte(`{"controller_endpoint":"https://x:3111","public_enrollment":true}`)); err == nil {
		t.Fatal("unknown key public_enrollment accepted")
	}
}

func TestAgentRejectsMalformedFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"missing-endpoint", `{}`},
		{"empty-endpoint", `{"controller_endpoint":""}`},
		{"bad-scheme", `{"controller_endpoint":"ftp://x:3111"}`},
		{"not-a-url", `{"controller_endpoint":"not a url"}`},
		{"port-overflow", `{"controller_endpoint":"https://x:65536"}`},
		{"bad-stun-url", `{"controller_endpoint":"https://x:3111","stun_servers":["http://stun.example.com"]}`},
		{"good-stun-urls", `{"controller_endpoint":"https://x:3111","stun_servers":["stun://s.example.com:3478","stun+tcp://s.example.com:3478"]}`},
		{"negative-uid", `{"controller_endpoint":"https://x:3111","dedicated_uid":-1}`},
		{"negative-gid", `{"controller_endpoint":"https://x:3111","dedicated_gid":-2}`},
		{"bad-log-level", `{"controller_endpoint":"https://x:3111","log_level":"chatty"}`},
		{"duplicate-key", `{"controller_endpoint":"https://x:3111","controller_endpoint":"https://y:3111"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "good-stun-urls" {
				if _, err := ParseAgentConfig([]byte(tc.raw)); err != nil {
					t.Fatalf("valid stun URLs rejected: %v", err)
				}
				return
			}
			if _, err := ParseAgentConfig([]byte(tc.raw)); err == nil {
				t.Fatalf("malformed agent config accepted: %s", tc.name)
			}
		})
	}
}

func TestTokenFileMode0600(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.token")
	if err := os.WriteFile(ok, []byte("secret-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose.token")
	if err := os.WriteFile(loose, []byte("secret-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "agent.conf")
	raw := `{"controller_endpoint":"https://x:3111","token_file":"` + ok + `"}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("load agent config with 0600 token failed: %v", err)
	}
	if agent.TokenFile != ok {
		t.Fatalf("token_file=%q", agent.TokenFile)
	}
	// A token file with loose permissions must fail closed.
	rawLoose := `{"controller_endpoint":"https://x:3111","token_file":"` + loose + `"}`
	loosePath := filepath.Join(dir, "loose.conf")
	if err := os.WriteFile(loosePath, []byte(rawLoose), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentConfig(loosePath); err == nil {
		t.Fatal("token file with mode 0644 accepted")
	}
	// Controller side same rule.
	ctlRaw := `{"enrollment_token_file":"` + loose + `"}`
	ctlPath := filepath.Join(dir, "controller.conf")
	if err := os.WriteFile(ctlPath, []byte(ctlRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControllerConfig(ctlPath); err == nil {
		t.Fatal("controller enrollment token file with mode 0644 accepted")
	}
}

func TestNoSecretLogging(t *testing.T) {
	agent, err := ParseAgentConfig([]byte(`{"controller_endpoint":"https://x:3111","token_file":"/var/lib/antinat/enroll.token"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := agent.Redacted().String()
	if strings.Contains(s, "enroll.token") {
		t.Fatalf("token path leaked into loggable representation: %s", s)
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Fatalf("redacted representation missing marker: %s", s)
	}
	ctl, err := ParseControllerConfig([]byte(`{"enrollment_token_file":"/etc/antinat/enroll.token"}`))
	if err != nil {
		t.Fatal(err)
	}
	cs := ctl.Redacted().String()
	if strings.Contains(cs, "enroll.token") {
		t.Fatalf("enrollment token path leaked: %s", cs)
	}
}

func TestControllerEndpointDefaultPort(t *testing.T) {
	// An https controller endpoint without a port defaults to 443.
	cfg, err := ParseAgentConfig([]byte(`{"controller_endpoint":"https://ctl.example.com"}`))
	if err != nil {
		t.Fatalf("endpoint without port rejected: %v", err)
	}
	if cfg.ControllerEndpoint != "https://ctl.example.com:443" {
		t.Fatalf("default port not applied: %q", cfg.ControllerEndpoint)
	}
}
