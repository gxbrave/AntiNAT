package install

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
)

// AgentConfig contains only non-secret runtime settings. Enrollment tokens
// are deliberately absent; the installer points ANTINAT_TOKEN_FILE at a
// one-time 0600 file and the Agent consumes/removes it after enrollment.
type AgentConfig struct {
	StateDir           string
	ControllerEndpoint string
	NodeID             string
	ControllerPin      string
	TokenFile          string
	BindInterface      string
	StunServers        string
	AutoOrder          string
}

// RenderAgentEnvironmentFile produces a systemd/Windows-compatible key/value
// file. Values are shell-quoted and no token value can enter the result because
// the type has no token field.
func RenderAgentEnvironmentFile(config AgentConfig) ([]byte, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	lines := []string{
		"ANTINAT_ENDPOINT=" + quoteEnvironmentValue(config.ControllerEndpoint),
		"ANTINAT_NODE=" + quoteEnvironmentValue(config.NodeID),
		"ANTINAT_STATE=" + quoteEnvironmentValue(config.StateDir),
	}
	if config.ControllerPin != "" {
		lines = append(lines, "ANTINAT_PIN="+quoteEnvironmentValue(config.ControllerPin))
	}
	if config.TokenFile != "" {
		lines = append(lines, "ANTINAT_TOKEN_FILE="+quoteEnvironmentValue(config.TokenFile))
	}
	if config.BindInterface != "" {
		lines = append(lines, "ANTINAT_BIND_INTERFACE="+quoteEnvironmentValue(config.BindInterface))
	}
	if config.StunServers != "" {
		lines = append(lines, "ANTINAT_STUN_SERVERS="+quoteEnvironmentValue(config.StunServers))
	}
	if config.AutoOrder != "" {
		lines = append(lines, "ANTINAT_AUTO_ORDER="+quoteEnvironmentValue(config.AutoOrder))
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func (c AgentConfig) validate() error {
	if c.StateDir == "" || c.ControllerEndpoint == "" || c.NodeID == "" {
		return errors.New("agent runtime config requires state dir, endpoint and node id")
	}
	if err := validateRuntimeURL(c.ControllerEndpoint); err != nil {
		return fmt.Errorf("controller endpoint: %w", err)
	}
	for name, value := range map[string]string{
		"state dir": c.StateDir, "node id": c.NodeID, "controller pin": c.ControllerPin,
		"token file": c.TokenFile, "bind interface": c.BindInterface,
		"stun servers": c.StunServers, "auto order": c.AutoOrder,
	} {
		if err := validateEnvironmentValue(name, value); err != nil {
			return err
		}
	}
	if c.ControllerPin != "" {
		if len(c.ControllerPin) != 64 || strings.ToLower(c.ControllerPin) != c.ControllerPin {
			return errors.New("controller pin must be 32-byte lowercase hexadecimal")
		}
		for _, r := range c.ControllerPin {
			if !strings.ContainsRune("0123456789abcdef", r) {
				return errors.New("controller pin must be hexadecimal")
			}
		}
	}
	return nil
}

func validateRuntimeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("endpoint must be an http(s) URL without credentials, query or fragment")
	}
	if u.Scheme == "http" && !runtimeLoopback(u.Hostname()) {
		return errors.New("non-loopback endpoint must use https")
	}
	return nil
}

func runtimeLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateEnvironmentValue(name, value string) error {
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) || r == '\n' || r == '\r' {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

func quoteEnvironmentValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
