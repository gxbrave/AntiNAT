package contracts

// Frozen AntiNAT installer and compatibility contract (docs/installer-contract.md).
//
// Pins:
//   - the install CLI surface (no secret in argv/env);
//   - token input semantics (TTY hidden / --token-fd / strict-ACL --token-file);
//   - frozen paths and service names (Linux systemd primary target);
//   - the frozen exit code registry;
//   - artifact trust rules (manifest + signed checksums, not a same-URL
//     checksum as the sole trust root);
//   - N/N-1 compatibility rules and purge semantics.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// Installer CLI contract
// ---------------------------------------------------------------------------

// installCommands are the frozen top-level installer verbs.
var installCommands = map[string]bool{
	"install":   true,
	"uninstall": true,
	"purge":     true,
	"upgrade":   true,
}

// installFlags is the frozen flag surface. Tokens are never accepted as a
// positional argument or a flag value; only --token-fd / --token-file.
var installFlags = map[string]bool{
	"--controller-endpoint": true,
	"--bind-interface":      true,
	"--install-dir":         true,
	"--service-name":        true,
	"--log-level":           true,
	"--auto-update":         true,
	"--github-proxy":        true,
	"--detection-scheduler": true,
	"--platform":            true,
	"--token-fd":            true,
	"--token-file":          true,
	"--version":             true,
	"--help":                true,
}

// forbiddenTokenFlags never exist: a literal token must never appear in argv.
var forbiddenTokenFlags = map[string]bool{
	"--token":       true,
	"--token-value": true,
	"-t":            true,
}

// platformNames are the frozen installer platform identifiers.
var platformNames = map[string]bool{
	"linux":   true,
	"windows": true,
	"docker":  true,
}

// ---------------------------------------------------------------------------
// Token input semantics
// ---------------------------------------------------------------------------

// tokenMode describes the three frozen ways an installer may receive the
// enrollment token.
type tokenMode string

const (
	tokenModeTTY  tokenMode = "tty"  // hidden TTY prompt (interactive default)
	tokenModeFD   tokenMode = "fd"   // --token-fd <n>: read from the open FD
	tokenModeFile tokenMode = "file" // --token-file <path>: strict-ACL 0600 file
)

// validateTokenInvocation enforces the frozen token input rules.
//   - exactly one of tty/fd/file must be selected;
//   - fd and file require their flag;
//   - a literal token argument is always rejected;
//   - file mode requires exactly 0600 (no stricter or looser mode).
func validateTokenInvocation(mode tokenMode, hasFD, hasFile bool, fileMode os.FileMode) error {
	selected := 0
	if mode == tokenModeTTY {
		selected++
	}
	if hasFD {
		selected++
	}
	if hasFile {
		selected++
	}
	if selected != 1 {
		return fmt.Errorf("exactly one token input must be selected (tty/fd/file), got %d", selected)
	}
	if mode == tokenModeFD && !hasFD {
		return errors.New("token mode fd requires --token-fd")
	}
	if mode == tokenModeFile && !hasFile {
		return errors.New("token mode file requires --token-file")
	}
	if mode == tokenModeFile && fileMode.Perm() != 0o600 {
		return fmt.Errorf("token file must be 0600, got %04o", fileMode.Perm())
	}
	return nil
}

// ---------------------------------------------------------------------------
// Frozen paths and services (Linux systemd primary target)
// ---------------------------------------------------------------------------

// installPaths are the frozen Linux install layout. Windows uses per-platform
// equivalents frozen in docs/installer-contract.md.
var installPaths = map[string]string{
	"install_dir":  "/opt/antinat",
	"binary":       "/opt/antinat/bin/antinat-agent",
	"data_dir":     "/var/lib/antinat",
	"config":       "/etc/antinat/agent.conf",
	"state_marker": "/var/lib/antinat/agent.marker",
	"log_dir":      "/var/log/antinat",
	"service":      "antinat-agent.service",
	"user":         "antinat",
	"group":        "antinat",
}

// validateInstallPath reports whether the named path has a frozen value.
func validateInstallPath(name, value string) error {
	want, ok := installPaths[name]
	if !ok {
		return fmt.Errorf("unknown install path key %q", name)
	}
	if value != want {
		return fmt.Errorf("install path %q = %q, want frozen %q", name, value, want)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Exit code registry
// ---------------------------------------------------------------------------

// installExitCodes is the frozen installer exit code registry.
var installExitCodes = map[int]string{
	0: "SUCCESS",
	1: "GENERIC_FAILURE",
	2: "USAGE_ERROR",
	3: "TOKEN_INPUT_FAILURE",
	4: "ARTIFACT_VERIFICATION_FAILURE",
	5: "PATH_OR_SERVICE_CONFLICT",
	6: "ROLLBACK_PERFORMED",
	7: "PURGE_COMPLETE",
	8: "UPGRADE_BLOCKED_MIGRATION_FAILURE",
}

func validateInstallExitCode(code int) error {
	if _, ok := installExitCodes[code]; !ok {
		return fmt.Errorf("unknown installer exit code %d", code)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Artifact trust
// ---------------------------------------------------------------------------

// validateArtifactManifest enforces the frozen artifact trust rules:
//   - the manifest carries per-artifact sha256;
//   - a detached signature covers the manifest (Ed25519 or compatible);
//   - the trust root is a pinned public key, never a checksum from the same
//     untrusted URL.
type artifactManifest struct {
	SchemaVersion string            `json:"schema_version"`
	Artifacts     map[string]string `json:"artifacts"` // path -> sha256
	HasSignature  bool              `json:"has_signature"`
	TrustRoot     string            `json:"trust_root"` // pinned key id
}

func validateArtifactManifest(m artifactManifest) error {
	if m.SchemaVersion != "1" {
		return fmt.Errorf("artifact manifest schema_version must be 1, got %q", m.SchemaVersion)
	}
	if len(m.Artifacts) == 0 {
		return errors.New("artifact manifest has no artifacts")
	}
	for path, sum := range m.Artifacts {
		if len(sum) != 64 {
			return fmt.Errorf("artifact %q checksum must be 64 hex chars", path)
		}
		for _, c := range sum {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return fmt.Errorf("artifact %q checksum is not lowercase hex", path)
			}
		}
	}
	if !m.HasSignature {
		return errors.New("artifact manifest must carry a detached signature")
	}
	if m.TrustRoot == "" {
		return errors.New("artifact manifest must name a pinned trust root")
	}
	return nil
}

// ---------------------------------------------------------------------------
// N/N-1 compatibility and purge
// ---------------------------------------------------------------------------

// validateNMinusOneState enforces the frozen upgrade compatibility rule:
// control/store schema from N-1 must be readable by N, and destructive schema
// changes are deferred one version.
func validateNMinusOneState(currentVersion, previousVersion uint64) error {
	if previousVersion == 0 {
		return errors.New("N-1 schema version must be non-zero")
	}
	if currentVersion < previousVersion {
		return fmt.Errorf("current schema %d < previous %d", currentVersion, previousVersion)
	}
	if currentVersion-previousVersion > 1 {
		return fmt.Errorf("schema jump %d -> %d skips an intermediate version", previousVersion, currentVersion)
	}
	return nil
}

// purgeState names the frozen purge lifecycle.
var purgeStates = map[string]bool{
	"NOTICE_SENT":          true,
	"BOUNDED_RECEIPT":      true,
	"CLEANED":              true,
	"NO_RESIDUE_CONFIRMED": true,
}

func validatePurgeState(state string) error {
	if !purgeStates[state] {
		return fmt.Errorf("unknown purge state %q", state)
	}
	return nil
}
