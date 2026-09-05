// Package deployment contains the secret-free deployment profile and command
// builder used by the Controller UI. It deliberately has no token field: an
// enrollment token is displayed once by the UI and is read by the installer
// from a hidden TTY, an open file descriptor, or a strict 0600 file.
package deployment

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
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
	releaseBaseURL     = "https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta"
	installerScriptURL = releaseBaseURL + "/install.sh"
	installerLibURL    = releaseBaseURL + "/libinstall.sh"
	installerPS1URL    = releaseBaseURL + "/install.ps1"
	installerTrustURL  = releaseBaseURL + "/release-ed25519.pub"
	installerScriptSHA = "a76fcd5150ea34cde8f02cf67ed56b64d561041a5698b8b9430be182c1e4c194"
	installerLibSHA    = "757c4ede3506961a0af106d3d9c63589e716de42097b1fcb55c8002adaed51f6"
	installerPS1SHA    = "db92ec929fb943df1debe51ae222814b3ad8e65147db070392b4bbb9a022fd9f"
	installerTrustSHA  = "7c250ef2c4b3ece394f1d22f106742152116ef192a89bda1f1deaef9073112f3"
	containerImage     = "ghcr.io/gxbrave/antinat-agent:v1.0.0-beta"
	dockerTokenSource  = "/secure/antinat/enrollment.token"
	dockerTokenTarget  = "/run/secrets/antinat_enrollment_token"
)

// InstallCommandContext contains the ephemeral identity and trust material
// needed to turn a saved profile into a usable enrollment command. It is
// intentionally separate from Profile so neither value can be persisted with
// deployment settings or confused with the one-time enrollment token.
type InstallCommandContext struct {
	NodeID        string
	ControllerPin string
}

func (c InstallCommandContext) validate() error {
	if strings.TrimSpace(c.NodeID) == "" {
		return errors.New("deployment: node id is required for command generation")
	}
	if err := validateText("node_id", c.NodeID); err != nil {
		return err
	}
	if len(c.ControllerPin) != hex.EncodedLen(ed25519.PublicKeySize) || c.ControllerPin != strings.ToLower(c.ControllerPin) {
		return errors.New("deployment: controller pin must be lowercase 32-byte hex")
	}
	if _, err := hex.DecodeString(c.ControllerPin); err != nil {
		return errors.New("deployment: controller pin must be lowercase 32-byte hex")
	}
	return nil
}

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
	endpoint, err := NormalizeOptionalServiceURL(p.ControllerEndpoint)
	if err != nil {
		return fmt.Errorf("deployment: controller endpoint: %w", err)
	}
	if strings.TrimSpace(p.ControllerEndpoint) == "" {
		return errors.New("deployment: controller endpoint is required")
	}
	if err := requireRemoteHTTPS("controller_endpoint", endpoint); err != nil {
		return err
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
		proxy, err := NormalizeOptionalServiceURL(p.GitHubProxy)
		if err != nil {
			return fmt.Errorf("deployment: github proxy: %w", err)
		}
		if err := requireRemoteHTTPS("github_proxy", proxy); err != nil {
			return err
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

func requireRemoteHTTPS(name, normalized string) error {
	u, err := url.Parse(normalized)
	if err != nil {
		return fmt.Errorf("deployment: invalid %s: %w", name, err)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("deployment: %s must use https for non-loopback hosts", name)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
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

// BuildInstallCommand creates the complete platform-specific command. The
// context carries only the node identity and public Controller pin; it never
// carries an enrollment token. The installer obtains that token through its
// hidden TTY/FD/file input contract.
func BuildInstallCommand(profile Profile, context InstallCommandContext) (string, error) {
	if err := profile.Validate(); err != nil {
		return "", err
	}
	if err := context.validate(); err != nil {
		return "", err
	}
	args, err := BuildAgentArguments(profile)
	if err != nil {
		return "", err
	}
	switch profile.Platform {
	case PlatformLinux:
		return buildPOSIXInstallCommand(
			installerURL(profile, installerScriptURL),
			installerURL(profile, installerLibURL),
			installerURL(profile, installerTrustURL),
			args, context), nil
	case PlatformWindows:
		return buildPowerShellInstallCommand(
			installerURL(profile, installerPS1URL),
			installerURL(profile, installerTrustURL),
			args, context), nil
	case PlatformDocker:
		return buildDockerCommand(profile, context), nil
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

func buildPOSIXInstallCommand(scriptURL, libraryURL, trustURL string, args []string, context InstallCommandContext) string {
	inner := "set -eu\n" +
		"tmp_dir=$(mktemp -d \"${TMPDIR:-/tmp}/antinat-installer.XXXXXX\")\n" +
		"trap 'rm -rf -- \"$tmp_dir\"' EXIT\n" +
		"mkdir -p -- \"$tmp_dir/scripts\" \"$tmp_dir/deploy/trust\"\n" +
		"curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 " + QuoteShellArg(scriptURL) + " -o \"$tmp_dir/scripts/install.sh\"\n" +
		"curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 " + QuoteShellArg(libraryURL) + " -o \"$tmp_dir/scripts/libinstall.sh\"\n" +
		"curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 " + QuoteShellArg(trustURL) + " -o \"$tmp_dir/deploy/trust/release-ed25519.pub\"\n" +
		"printf '%s  %s\\n' '" + installerScriptSHA + "' \"$tmp_dir/scripts/install.sh\" | sha256sum --check --status -\n" +
		"printf '%s  %s\\n' '" + installerLibSHA + "' \"$tmp_dir/scripts/libinstall.sh\" | sha256sum --check --status -\n" +
		"printf '%s  %s\\n' '" + installerTrustSHA + "' \"$tmp_dir/deploy/trust/release-ed25519.pub\" | sha256sum --check --status -\n" +
		"chmod 700 -- \"$tmp_dir\" \"$tmp_dir/scripts\" \"$tmp_dir/deploy\" \"$tmp_dir/deploy/trust\"\n" +
		"chmod 600 -- \"$tmp_dir/scripts/install.sh\" \"$tmp_dir/scripts/libinstall.sh\" \"$tmp_dir/deploy/trust/release-ed25519.pub\"\n" +
		"sudo env " + QuoteShellArg("ANTINAT_NODE_ID="+context.NodeID) + " " +
		QuoteShellArg("ANTINAT_CONTROLLER_PIN="+context.ControllerPin) +
		" bash \"$tmp_dir/scripts/install.sh\" install " + QuoteShellArgs(args)
	return "bash -o pipefail -c " + QuoteShellArg(inner)
}

func buildPowerShellInstallCommand(scriptURL, trustURL string, args []string, context InstallCommandContext) string {
	psArgs := make([]string, 0, len(args)+1)
	psArgs = append(psArgs, "install")
	for _, arg := range args {
		psArgs = append(psArgs, QuotePowerShellArg(arg))
	}
	body := "$temp = Join-Path ([IO.Path]::GetTempPath()) ('antinat-installer-' + [Guid]::NewGuid().ToString('N')); " +
		"$scriptPath = Join-Path $temp 'scripts\\install.ps1'; " +
		"$trustPath = Join-Path $temp 'deploy\\trust\\release-ed25519.pub'; " +
		"New-Item -ItemType Directory -Path (Join-Path $temp 'scripts'), (Join-Path $temp 'deploy\\trust') | Out-Null; " +
		"try { " +
		"Invoke-WebRequest -UseBasicParsing -Uri " + QuotePowerShellArg(scriptURL) + " -OutFile $scriptPath; " +
		"Invoke-WebRequest -UseBasicParsing -Uri " + QuotePowerShellArg(trustURL) + " -OutFile $trustPath; " +
		"if ((Get-FileHash -Algorithm SHA256 -LiteralPath $scriptPath).Hash.ToLowerInvariant() -ne '" + installerPS1SHA + "') { throw 'installer hash verification failed' }; " +
		"if ((Get-FileHash -Algorithm SHA256 -LiteralPath $trustPath).Hash.ToLowerInvariant() -ne '" + installerTrustSHA + "') { throw 'trust root hash verification failed' }; " +
		"$env:ANTINAT_NODE_ID = " + QuotePowerShellArg(context.NodeID) +
		"; $env:ANTINAT_CONTROLLER_PIN = " + QuotePowerShellArg(context.ControllerPin) +
		"; & $scriptPath " + strings.Join(psArgs, " ") +
		" } finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }"
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

func buildDockerCommand(profile Profile, context InstallCommandContext) string {
	endpoint, _ := NormalizeOptionalServiceURL(profile.ControllerEndpoint)
	dataVolume, logVolume := dockerVolumeNames(context.NodeID)
	env := []string{
		"ANTINAT_ENDPOINT=" + endpoint,
		"ANTINAT_NODE=" + context.NodeID,
		"ANTINAT_PIN=" + context.ControllerPin,
		"ANTINAT_STATE=/var/lib/antinat",
		"ANTINAT_DOCKER_TOKEN_FILE=" + dockerTokenTarget,
	}
	renderedEnv := make([]string, 0, len(env))
	for _, value := range env {
		renderedEnv = append(renderedEnv, "--env "+QuoteShellArg(value))
	}
	helperScript := `set -eu
state=/var/lib/antinat
install -d -o 65532 -g 65532 -m 700 "$state"
if [ -e "$state/.enrollment-complete" ]; then
    exit 0
fi
if [ -e "$state/.enrollment-token" ] || [ -L "$state/.enrollment-token" ]; then
    [ -f "$state/.enrollment-token" ] && [ ! -L "$state/.enrollment-token" ]
    [ "$(stat -c '%u:%g:%a' "$state/.enrollment-token")" = 65532:65532:600 ]
    exit 0
fi
[ -f /run/input/enrollment.token ] && [ ! -L /run/input/enrollment.token ]
install -o 65532 -g 65532 -m 600 /run/input/enrollment.token "$state/.enrollment-token"`
	helper := "docker run --rm --read-only --network none --user 0:0 " +
		"--mount " + QuoteShellArg("type=bind,src="+dockerTokenSource+",dst=/run/input/enrollment.token,readonly") + " " +
		"--mount " + QuoteShellArg("type=volume,src="+dataVolume+",dst=/var/lib/antinat") + " " +
		"--entrypoint /bin/sh " + containerImage + " -c " + QuoteShellArg(helperScript)
	return helper + " && docker run --interactive --tty --network host --restart=always " +
		strings.Join(renderedEnv, " ") + " " +
		"--user 65532:65532 " +
		"--mount " + QuoteShellArg("type=volume,src="+dataVolume+",dst=/var/lib/antinat") + " " +
		"--mount " + QuoteShellArg("type=volume,src="+logVolume+",dst=/var/log/antinat") + " " +
		containerImage
}

func dockerVolumeNames(nodeID string) (string, string) {
	digest := fnv.New32a()
	_, _ = digest.Write([]byte(nodeID))
	suffix := fmt.Sprintf("%08x", digest.Sum32())
	return "antinat-agent-data-" + suffix, "antinat-agent-log-" + suffix
}

// InstallerScriptURL returns the default script URL for callers that need to
// show provenance alongside the generated command.
func InstallerScriptURL(platform string) string {
	if platform == PlatformWindows {
		return installerPS1URL
	}
	return installerScriptURL
}
