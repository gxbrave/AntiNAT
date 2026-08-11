package state

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDecommissionCrashMatrix(t *testing.T) {
	phases := []string{"intent", "marker", "side_effect", "result", "ack", "receipt"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			if err := InitializeDecommissionFixture(dir); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=TestDecommissionCrashHelper", "--", dir, phase)
			cmd.Env = append(os.Environ(), "ANTINAT_CRASH_HELPER=1")
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("helper phase %s: err=%v output=%s", phase, err, output)
			}

			state, err := RecoverDecommission(dir)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "intent" {
				if state.Marker != "" || !state.LKGPresent || !state.SecretPresent {
					t.Fatalf("intent recovery = %+v, want old LKG and secret preserved without marker", state)
				}
				return
			}
			if state.Marker != "DECOMMISSIONED" || state.LKGPresent || state.SecretPresent {
				t.Fatalf("%s recovery = %+v, want terminal cleanup without resurrection", phase, state)
			}
			wantAck := phase != "receipt"
			if state.AckPending != wantAck {
				t.Fatalf("%s AckPending = %v, want %v", phase, state.AckPending, wantAck)
			}
		})
	}
}

func TestDecommissionCrashHelper(t *testing.T) {
	if os.Getenv("ANTINAT_CRASH_HELPER") != "1" {
		return
	}
	args := os.Args
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || len(args) != separator+3 {
		os.Exit(92)
	}
	dir, phase := args[separator+1], args[separator+2]
	if err := Decommission(dir, func(reached string) {
		if reached == phase {
			os.Exit(91)
		}
	}); err != nil {
		os.Exit(93)
	}
	os.Exit(94)
}

func TestAtomicSecretFileUsesRestrictivePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	if err := WriteSecretFileAtomic(path, []byte("test-secret")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("secret mode = %#o, want 0600", got)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "test-secret" {
		t.Fatalf("secret read = %q, %v", data, err)
	}
}

func TestAtomicSecretFileRestrictsExistingStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFileAtomic(filepath.Join(dir, "identity.key"), []byte("test-secret")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %#o, want 0700", got)
	}
}
