// Package install contains the platform-neutral safety primitives used by the
// AntiNAT installers. The shell and PowerShell entry points deliberately keep
// their policy surface small; parsing, token handling and filesystem
// transactions live here so the two installers share the same contract.
package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Installer commands are frozen by docs/installer-contract.md.
type Command string

const (
	CommandInstall   Command = "install"
	CommandUninstall Command = "uninstall"
	CommandPurge     Command = "purge"
	CommandUpgrade   Command = "upgrade"
)

// Platform names are the frozen deployment identifiers.
const (
	PlatformLinux   = "linux"
	PlatformWindows = "windows"
	PlatformDocker  = "docker"
)

// Exit codes are intentionally stable because bootstrap callers use them for
// automation and because a rollback must be distinguishable from a generic
// failure.
type ExitCode int

const (
	ExitSuccess                 ExitCode = 0
	ExitGenericFailure          ExitCode = 1
	ExitUsageError              ExitCode = 2
	ExitTokenInputFailure       ExitCode = 3
	ExitArtifactVerification    ExitCode = 4
	ExitPathOrServiceConflict   ExitCode = 5
	ExitRollbackPerformed       ExitCode = 6
	ExitPurgeComplete           ExitCode = 7
	ExitUpgradeMigrationBlocked ExitCode = 8
)

var exitNames = map[ExitCode]string{
	ExitSuccess:                 "SUCCESS",
	ExitGenericFailure:          "GENERIC_FAILURE",
	ExitUsageError:              "USAGE_ERROR",
	ExitTokenInputFailure:       "TOKEN_INPUT_FAILURE",
	ExitArtifactVerification:    "ARTIFACT_VERIFICATION_FAILURE",
	ExitPathOrServiceConflict:   "PATH_OR_SERVICE_CONFLICT",
	ExitRollbackPerformed:       "ROLLBACK_PERFORMED",
	ExitPurgeComplete:           "PURGE_COMPLETE",
	ExitUpgradeMigrationBlocked: "UPGRADE_BLOCKED_MIGRATION_FAILURE",
}

// Name returns the frozen symbolic name for an exit code.
func (c ExitCode) Name() string { return exitNames[c] }

// InstallerError carries the exit code that a platform entry point should
// return without exposing secrets in the error text.
type InstallerError struct {
	Code  ExitCode
	Op    string
	Cause error
}

func (e *InstallerError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return e.Op
	}
	if e.Op == "" {
		return e.Cause.Error()
	}
	return e.Op + ": " + e.Cause.Error()
}

func (e *InstallerError) Unwrap() error { return e.Cause }

// CodeOf maps an error to the stable installer exit code.
func CodeOf(err error) ExitCode {
	if err == nil {
		return ExitSuccess
	}
	var ie *InstallerError
	if errors.As(err, &ie) {
		return ie.Code
	}
	return ExitGenericFailure
}

// Options is the parsed frozen installer command line. Token bytes never live
// in this structure; TokenFD and TokenFile only identify protected inputs.
type Options struct {
	Command Command

	ControllerEndpoint string
	BindInterface      string
	InstallDir         string
	ServiceName        string
	LogLevel           string
	AutoUpdate         string
	GitHubProxy        string
	DetectionScheduler string
	Platform           string
	TokenFD            int
	TokenFile          string

	Help    bool
	Version bool
}

var installerCommands = map[Command]bool{
	CommandInstall:   true,
	CommandUninstall: true,
	CommandPurge:     true,
	CommandUpgrade:   true,
}

type flagSpec struct{ takesValue bool }

var installerFlags = map[string]flagSpec{
	"--controller-endpoint": {takesValue: true},
	"--bind-interface":      {takesValue: true},
	"--install-dir":         {takesValue: true},
	"--service-name":        {takesValue: true},
	"--log-level":           {takesValue: true},
	"--auto-update":         {takesValue: true},
	"--github-proxy":        {takesValue: true},
	"--detection-scheduler": {takesValue: true},
	"--platform":            {takesValue: true},
	"--token-fd":            {takesValue: true},
	"--token-file":          {takesValue: true},
	"--version":             {takesValue: false},
	"--help":                {takesValue: false},
}

// Parse parses the exact public installer command line. It rejects positional
// values and unknown flags, which also prevents a literal enrollment token
// from being smuggled through an unrecognised argument.
func Parse(args []string) (Options, error) {
	o := Options{TokenFD: -1, Platform: PlatformLinux}
	if len(args) == 0 {
		return o, usageError("a command is required")
	}
	if !strings.HasPrefix(args[0], "-") {
		o.Command = Command(args[0])
		if !installerCommands[o.Command] {
			return o, usageError("unknown command " + strconv.Quote(args[0]))
		}
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		raw := args[i]
		if raw == "--help" {
			o.Help = true
			continue
		}
		if raw == "--version" {
			o.Version = true
			continue
		}
		if !strings.HasPrefix(raw, "--") {
			return o, usageError("positional arguments are not accepted")
		}
		name, value, hasValue := splitFlag(raw)
		if name == "--token" || name == "--token-value" {
			return o, usageError("literal token arguments are forbidden")
		}
		if strings.HasPrefix(name, "--token-") && name != "--token-fd" && name != "--token-file" {
			return o, usageError("unknown token input flag " + name)
		}
		spec, ok := installerFlags[name]
		if !ok {
			return o, usageError("unknown installer flag " + name)
		}
		if !spec.takesValue {
			if hasValue {
				return o, usageError(name + " does not take a value")
			}
			continue
		}
		if !hasValue {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return o, usageError(name + " requires a value")
			}
			i++
			value = args[i]
		}
		if value == "" {
			return o, usageError(name + " requires a non-empty value")
		}
		switch name {
		case "--controller-endpoint":
			o.ControllerEndpoint = value
		case "--bind-interface":
			o.BindInterface = value
		case "--install-dir":
			o.InstallDir = value
		case "--service-name":
			o.ServiceName = value
		case "--log-level":
			o.LogLevel = value
		case "--auto-update":
			o.AutoUpdate = value
		case "--github-proxy":
			o.GitHubProxy = value
		case "--detection-scheduler":
			o.DetectionScheduler = value
		case "--platform":
			o.Platform = value
		case "--token-fd":
			fd, err := strconv.Atoi(value)
			if err != nil || fd < 3 {
				return o, usageError("--token-fd must be an open descriptor >= 3")
			}
			o.TokenFD = fd
		case "--token-file":
			o.TokenFile = value
		}
	}
	if o.Command == "" && !o.Help && !o.Version {
		return o, usageError("a command is required")
	}
	if o.Command != CommandInstall && (o.TokenFD >= 0 || o.TokenFile != "") {
		return o, usageError("token input is only valid for install")
	}
	if o.Platform != PlatformLinux && o.Platform != PlatformWindows && o.Platform != PlatformDocker {
		return o, usageError("unsupported platform " + strconv.Quote(o.Platform))
	}
	if o.TokenFD >= 0 && o.TokenFile != "" {
		return o, usageError("--token-fd and --token-file are mutually exclusive")
	}
	return o, nil
}

func splitFlag(raw string) (name, value string, hasValue bool) {
	name = raw
	if at := strings.IndexByte(raw, '='); at >= 0 {
		return raw[:at], raw[at+1:], true
	}
	return name, "", false
}

func usageError(message string) error {
	return &InstallerError{Code: ExitUsageError, Op: "usage", Cause: errors.New(message)}
}

// TokenMode is one of the three frozen enrollment-token sources.
type TokenMode string

const (
	TokenTTY  TokenMode = "tty"
	TokenFD   TokenMode = "fd"
	TokenFile TokenMode = "file"
)

// ValidateTokenInvocation checks the source selection independently from the
// actual filesystem. File mode is checked again by OpenTokenInput after opening
// the file, closing the TOCTOU gap between validation and use.
func ValidateTokenInvocation(mode TokenMode, fd int, file string, fileMode os.FileMode) error {
	selected := 0
	if mode == TokenTTY {
		selected++
	}
	if fd != -1 && fd != 0 {
		selected++
	}
	if file != "" {
		selected++
	}
	if selected != 1 {
		return &InstallerError{Code: ExitTokenInputFailure, Op: "token", Cause: fmt.Errorf("exactly one token input is required, got %d", selected)}
	}
	if mode == TokenFD && (fd < 3 || fd == 0) {
		return &InstallerError{Code: ExitTokenInputFailure, Op: "token", Cause: errors.New("token fd must be >= 3")}
	}
	if mode == TokenFile && file == "" {
		return &InstallerError{Code: ExitTokenInputFailure, Op: "token", Cause: errors.New("token file is required")}
	}
	if mode == TokenFile && fileMode.Perm() != 0o600 {
		return &InstallerError{Code: ExitTokenInputFailure, Op: "token", Cause: fmt.Errorf("token file must have mode 0600, got %04o", fileMode.Perm())}
	}
	return nil
}

// TokenInput holds a token in memory and an identity-bound cleanup operation.
// Call Commit only after the enrollment transaction has succeeded. Abort keeps
// a file token available for a retry and always closes the open descriptor.
type TokenInput struct {
	token     string
	commit    func() error
	close     func() error
	path      string
	committed bool
}

// Token returns the protected token bytes. Callers must not log or persist the
// returned value.
func (t *TokenInput) Token() string {
	if t == nil {
		return ""
	}
	return t.token
}

// Path returns the source path for file-backed input, or an empty string for a
// TTY/descriptor source.
func (t *TokenInput) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

// Commit consumes a file-backed token after successful enrollment.
func (t *TokenInput) Commit() error {
	if t == nil || t.committed {
		return nil
	}
	if t.commit != nil {
		if err := t.commit(); err != nil {
			return err
		}
	}
	t.committed = true
	return t.Close()
}

// Abort closes input without consuming a file-backed token.
func (t *TokenInput) Abort() error { return t.Close() }

// Close releases open descriptors. It is idempotent.
func (t *TokenInput) Close() error {
	if t == nil || t.close == nil {
		return nil
	}
	closeFn := t.close
	t.close = nil
	return closeFn()
}

// ReadTokenFromReader reads a bounded token for test harnesses and TTY
// adapters. A final line ending is accepted; embedded whitespace is not.
func ReadTokenFromReader(r io.Reader) (string, error) {
	if r == nil {
		return "", &InstallerError{Code: ExitTokenInputFailure, Op: "token", Cause: errors.New("token reader is nil")}
	}
	return readTokenBytes(r)
}
