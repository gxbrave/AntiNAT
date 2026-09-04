// Package deployment contains the secret-free deployment profile and command
// builder used by the Controller UI. It deliberately has no token field: an
// enrollment token is displayed once by the UI and is read by the installer
// from a hidden TTY, an open file descriptor, or a strict 0600 file.
package deployment

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf16"
)

const (
	PlatformLinux   = "linux"
	PlatformWindows = "windows"
	PlatformDocker  = "docker"

	defaultInstallDir  = "/opt/antinat"
	defaultServiceName = "antinat-agent.service"
	defaultLogLevel    = "info"
	defaultAutoUpdate  = "disabled"
	defaultScheduler   = "sequential"
	installerScriptURL = "https://github.com/gxbrave/AntiNAT/releases/latest/download/install.sh"
	installerPS1URL    = "https://github.com/gxbrave/AntiNAT/releases/latest/download/install.ps1"
	containerImage     = "ghcr.io/gxbrave/antinat-agent:latest"
)

// Profile is the persisted, structured deployment configuration. It contains
// no enrollment token and no generated command string. User-provided values
// remain values until the final platform-specific command rendering step.
type Profile struct {
	Platform           string `json:"platform"`
	ControllerEndpoint string `json:"controller_endpoint"`
	BindInterface      string `json:"bind_interface,omitempty"`
	DetectionScheduler string `json:"detection_scheduler,omitempty"`
	GitHubProxy        string `json:"github_proxy,omitempty"`
	InstallDir         string `json:"install_dir,omitempty"`
	ServiceName        string `json:"service_name,omitempty"`
	LogLevel           string `json:"log_level,omitempty"`
	AutoUpdate         string `json:"auto_update,omitempty"`
}

// DefaultProfile returns a complete safe starting profile for a new node.
func DefaultProfile(controllerEndpoint string) Profile {
	return Profile{
		Platform:           PlatformLinux,
		ControllerEndpoint: strings.TrimSpace(controllerEndpoint),
		DetectionScheduler: defaultScheduler,
		InstallDir:         defaultInstallDir,
		ServiceName:        defaultServiceName,
		LogLevel:           defaultLogLevel,
		AutoUpdate:         defaultAutoUpdate,
	}
}

// Validate normalizes and validates the fields that have semantic constraints.
// Shell metacharacters in ordinary values are allowed and escaped at render
// time; rejecting them here would not be a security boundary and would make
// valid interface/path names needlessly unusable.
func (p Profile) Validate() error {
	switch p.Platform {
	case PlatformLinux, PlatformWindows, PlatformDocker:
	default:
		return fmt.Errorf("deployment: unsupported platform %q", p.Platform)
	}
	if _, err := NormalizeOptionalServiceURL(p.ControllerEndpoint); err != nil {
		return fmt.Errorf("deployment: controller endpoint: %w", err)
	}
	if strings.TrimSpace(p.ControllerEndpoint) == "" {
		return errors.New("deployment: controller endpoint is required")
	}
	for name, value := range map[string]string{
		"bind_interface":      p.BindInterface,
		"install_dir":         p.InstallDir,
		"service_name":        p.ServiceName,
		"github_proxy":        p.GitHubProxy,
		"detection_scheduler": p.DetectionScheduler,
		"log_level":           p.LogLevel,
		"auto_update":         p.AutoUpdate,
	} {
		if err := validateText(name, value); err != nil {
			return err
		}
	}
	if p.GitHubProxy != "" {
		if _, err := NormalizeOptionalServiceURL(p.GitHubProxy); err != nil {
			return fmt.Errorf("deployment: github proxy: %w", err)
		}
	}
	if p.DetectionScheduler != "" && p.DetectionScheduler != "sequential" && p.DetectionScheduler != "parallel" {
		return fmt.Errorf("deployment: detection_scheduler must be sequential or parallel, got %q", p.DetectionScheduler)
	}
	if p.LogLevel != "" {
		switch p.LogLevel {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("deployment: unsupported log_level %q", p.LogLevel)
		}
	}
	if p.AutoUpdate != "" {
		switch p.AutoUpdate {
		case "disabled", "manual", "stable", "enabled":
		default:
			return fmt.Errorf("deployment: unsupported auto_update policy %q", p.AutoUpdate)
		}
	}
	return nil
}

func (p Profile) ValidateComplete() error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.DetectionScheduler == "" {
		return errors.New("deployment: detection_scheduler is required")
	}
	if p.LogLevel == "" {
		return errors.New("deployment: log_level is required")
	}
	if p.AutoUpdate == "" {
		return errors.New("deployment: auto_update is required")
	}
	return nil
}

func validateText(name, value string) error {
	if len(value) > 1024 {
		return fmt.Errorf("deployment: %s exceeds 1024 bytes", name)
	}
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return fmt.Errorf("deployment: %s contains a control character", name)
		}
	}
	return nil
}

// NormalizeOptionalServiceURL normalizes a URL field used by the deployment
// form. Empty is allowed for an optional proxy; non-empty values receive an
// https scheme when omitted, accept only http/https, reject credentials,
// queries/fragments and whitespace, and have trailing path slashes removed.
func NormalizeOptionalServiceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	for _, r := range raw {
		if r == 0 || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", errors.New("url contains whitespace or control characters")
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("host is required")
	}
	if u.User != nil {
		return "", errors.New("userinfo is not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("query and fragment are not allowed")
	}
	if strings.ContainsAny(u.Host, "\\\"'<>[]") {
		return "", errors.New("host contains unsafe characters")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// QuoteShellArg quotes one argument for POSIX sh/bash. It is safe for empty
// strings and for arbitrary printable user input.
func QuoteShellArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// QuoteShellArgs quotes and joins arguments for a POSIX command line.
func QuoteShellArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = QuoteShellArg(arg)
	}
	return strings.Join(quoted, " ")
}

// QuotePowerShellArg quotes one argument for PowerShell's single-quoted
// literal syntax. A single quote is represented by two single quotes.
func QuotePowerShellArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// BuildAgentArguments maps a profile to the frozen installer flags. The return
// value is a slice of raw arguments, not a shell string, so callers cannot
// accidentally mix quoting rules between platforms.
func BuildAgentArguments(profile Profile) ([]string, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	endpoint, err := NormalizeOptionalServiceURL(profile.ControllerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("deployment: normalize endpoint: %w", err)
	}
	args := []string{"--platform", profile.Platform, "--controller-endpoint", endpoint}
	if profile.BindInterface != "" {
		args = append(args, "--bind-interface", profile.BindInterface)
	}
	scheduler := profile.DetectionScheduler
	if scheduler == "" {
		scheduler = defaultScheduler
	}
	args = append(args, "--detection-scheduler", scheduler)
	logLevel := profile.LogLevel
	if logLevel == "" {
		logLevel = defaultLogLevel
	}
	args = append(args, "--log-level", logLevel)
	autoUpdate := profile.AutoUpdate
	if autoUpdate == "" {
		autoUpdate = defaultAutoUpdate
	}
	args = append(args, "--auto-update", autoUpdate)

	// Docker is an already-launched image. Installer-only flags would either
	// be ignored or leak an implementation detail into the container command.
	if profile.Platform != PlatformDocker {
		if profile.GitHubProxy != "" {
			proxy, _ := NormalizeOptionalServiceURL(profile.GitHubProxy)
			args = append(args, "--github-proxy", proxy)
		}
		if profile.InstallDir != "" {
			args = append(args, "--install-dir", profile.InstallDir)
		}
		if profile.ServiceName != "" {
			args = append(args, "--service-name", profile.ServiceName)
		}
	}
	return args, nil
}

// BuildInstallCommand creates the complete platform-specific command. No
// function argument or profile field carries a token, so the resulting command
// cannot contain an enrollment secret. The installer itself obtains the token
// through its hidden TTY/FD/file input contract.
func BuildInstallCommand(profile Profile) (string, error) {
	if err := profile.Validate(); err != nil {
		return "", err
	}
	args, err := BuildAgentArguments(profile)
	if err != nil {
		return "", err
	}
	switch profile.Platform {
	case PlatformLinux:
		return buildPOSIXInstallCommand(installerURL(profile, installerScriptURL), args), nil
	case PlatformWindows:
		return buildPowerShellInstallCommand(installerURL(profile, installerPS1URL), args), nil
	case PlatformDocker:
		return buildDockerCommand(args), nil
	default:
		return "", fmt.Errorf("deployment: unsupported platform %q", profile.Platform)
	}
}

func installerURL(profile Profile, base string) string {
	if profile.GitHubProxy == "" || profile.Platform == PlatformDocker {
		return base
	}
	proxy, err := NormalizeOptionalServiceURL(profile.GitHubProxy)
	if err != nil {
		return base
	}
	return strings.TrimRight(proxy, "/") + "/" + base
}

func buildPOSIXInstallCommand(scriptURL string, args []string) string {
	return "curl --fail --silent --show-error --location " + QuoteShellArg(scriptURL) +
		" | sudo bash -s -- install " + QuoteShellArgs(args)
}

func buildPowerShellInstallCommand(scriptURL string, args []string) string {
	psArgs := make([]string, 0, len(args)+1)
	psArgs = append(psArgs, "install")
	for _, arg := range args {
		psArgs = append(psArgs, QuotePowerShellArg(arg))
	}
	body := "$script = (Invoke-WebRequest -UseBasicParsing -Uri " + QuotePowerShellArg(scriptURL) +
		").Content; & ([scriptblock]::Create($script)) " + strings.Join(psArgs, " ")
	return "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encodePowerShellCommand(body)
}

func encodePowerShellCommand(command string) string {
	units := utf16.Encode([]rune(command))
	bytes := make([]byte, len(units)*2)
	for i, unit := range units {
		bytes[i*2] = byte(unit)
		bytes[i*2+1] = byte(unit >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func buildDockerCommand(args []string) string {
	// Keep the platform marker readable in the command while quoting every
	// value-bearing argument. The marker is a package constant, never user
	// input; endpoint/interface paths still use POSIX quoting.
	rendered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--platform" && i+1 < len(args) {
			rendered = append(rendered, "--platform "+args[i+1])
			i++
			continue
		}
		rendered = append(rendered, QuoteShellArg(args[i]))
	}
	return "docker run --network host --restart=always " +
		"--volume /var/lib/antinat:/var/lib/antinat " + containerImage + " " + strings.Join(rendered, " ")
}

// InstallerScriptURL returns the default script URL for callers that need to
// show provenance alongside the generated command.
func InstallerScriptURL(platform string) string {
	if platform == PlatformWindows {
		return installerPS1URL
	}
	return installerScriptURL
}
