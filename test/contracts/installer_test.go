package contracts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installerFixture is the frozen fixture schema for installer/compat vectors.
//
// Kinds:
//   - "cli": asserts a CLI invocation shape is valid or invalid (no token
//     literal in argv; only frozen flags).
//   - "token": asserts token input mode rules (exactly one of tty/fd/file;
//     file requires 0600).
//   - "path": asserts a frozen install path value.
//   - "exit": asserts a frozen installer exit code.
//   - "artifact": asserts an artifact manifest satisfies trust rules.
//   - "compat": asserts an N/N-1 schema-version pair is valid.
//   - "purge": asserts a purge state is frozen.
type installerFixture struct {
	Schema   string `json:"schema"`
	VectorID string `json:"vector_id"`
	Kind     string `json:"kind"`
	Expect   string `json:"expect"`

	// cli
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`

	// token
	TokenMode string `json:"token_mode,omitempty"` // tty|fd|file
	HasFD     bool   `json:"has_fd,omitempty"`
	HasFile   bool   `json:"has_file,omitempty"`
	FileMode  uint32 `json:"file_mode,omitempty"`

	// path
	PathKey   string `json:"path_key,omitempty"`
	PathValue string `json:"path_value,omitempty"`

	// exit
	ExitCode int `json:"exit_code,omitempty"`

	// artifact
	Artifact artifactManifest `json:"artifact,omitempty"`

	// compat
	CurrentVersion  uint64 `json:"current_version,omitempty"`
	PreviousVersion uint64 `json:"previous_version,omitempty"`

	// purge
	PurgeState string `json:"purge_state,omitempty"`
}

func TestInstallerContractGoldenVectors(t *testing.T) {
	dirs := []string{
		filepath.Join(repoRoot(t), "test", "fixtures", "installer-contract"),
		filepath.Join(repoRoot(t), "test", "fixtures", "compat"),
	}
	total := 0
	for _, dir := range dirs {
		files := walkJSONFiles(t, dir)
		total += len(files)
		for _, path := range files {
			path := path
			t.Run(filepath.Base(path), func(t *testing.T) {
				var fx installerFixture
				loadFixtureJSON(t, path, &fx)
				if fx.Schema != "antinat.contracts/installer/v1" && fx.Schema != "antinat.contracts/compat/v1" {
					t.Fatalf("unexpected schema %q", fx.Schema)
				}
				validateInstallerFixture(t, fx)
			})
		}
	}
	if total == 0 {
		t.Fatalf("no installer/compat fixtures found under %v", dirs)
	}
}

func validateInstallerFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	switch fx.Kind {
	case "cli":
		validateCLIFixture(t, fx)
	case "token":
		validateTokenFixture(t, fx)
	case "path":
		validatePathFixture(t, fx)
	case "exit":
		validateExitFixture(t, fx)
	case "artifact":
		validateArtifactFixture(t, fx)
	case "compat":
		validateCompatFixture(t, fx)
	case "purge":
		validatePurgeFixture(t, fx)
	default:
		t.Fatalf("unknown installer fixture kind %q", fx.Kind)
	}
}

func validateCLIFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	if !installCommands[fx.Command] {
		t.Fatalf("unknown install command %q", fx.Command)
	}
	err := validateCLIArgs(fx.Command, fx.Args)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid CLI rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid CLI accepted")
		}
	default:
		t.Fatalf("cli expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validateCLIArgs(command string, args []string) error {
	for i, a := range args {
		// A literal token argument is always forbidden.
		if forbiddenTokenFlags[a] {
			return errors.New("forbidden token flag in argv")
		}
		// No short flags exist in the frozen surface; any "-x" is unknown.
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && a != "-" {
			return errors.New("unknown short flag " + a)
		}
		if strings.HasPrefix(a, "--") {
			name := a
			hasValue := false
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				name = a[:eq]
				hasValue = true
			}
			if !installFlags[name] {
				return errors.New("unknown installer flag " + name)
			}
			// --token-fd / --token-file require a value; a bare flag with no
			// `=value` and no following non-flag argument is rejected.
			if (name == "--token-fd" || name == "--token-file") && !hasValue {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					return errors.New("flag " + name + " requires a value")
				}
			}
		}
	}
	return nil
}

func validateTokenFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	mode := tokenMode(fx.TokenMode)
	if mode != tokenModeTTY && mode != tokenModeFD && mode != tokenModeFile {
		t.Fatalf("unknown token_mode %q", fx.TokenMode)
	}
	err := validateTokenInvocation(mode, fx.HasFD, fx.HasFile, os.FileMode(fx.FileMode))
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid token invocation rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid token invocation accepted")
		}
	default:
		t.Fatalf("token expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validatePathFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	err := validateInstallPath(fx.PathKey, fx.PathValue)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid path rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid path accepted")
		}
	default:
		t.Fatalf("path expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validateExitFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	err := validateInstallExitCode(fx.ExitCode)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid exit code rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid exit code accepted")
		}
	default:
		t.Fatalf("exit expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validateArtifactFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	err := validateArtifactManifest(fx.Artifact)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid artifact manifest rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid artifact manifest accepted")
		}
	default:
		t.Fatalf("artifact expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validateCompatFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	err := validateNMinusOneState(fx.CurrentVersion, fx.PreviousVersion)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid N/N-1 pair rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid N/N-1 pair accepted")
		}
	default:
		t.Fatalf("compat expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validatePurgeFixture(t *testing.T, fx installerFixture) {
	t.Helper()
	err := validatePurgeState(fx.PurgeState)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid purge state rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid purge state accepted")
		}
	default:
		t.Fatalf("purge expect must be valid or invalid, got %q", fx.Expect)
	}
}
