package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/api"
	"github.com/gxbrave/AntiNAT/internal/controller/auth"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/controller/web"
	"net/http/httptest"
)

// buildCLI builds the antinatctl binary into a temp dir.
func buildCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "antinatctl")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/gxbrave/AntiNAT/cmd/antinatctl")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build antinatctl: %v (%s)", err, out)
	}
	return bin
}

// repoRoot returns the module root (two levels up from cmd/antinatctl).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(dir))
}

// startAPIServer starts the minimal API server for CLI integration.
func startAPIServer(t *testing.T) (string, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	handler, err := web.NewRouter(api.RouterConfig{Store: st, Auth: auth.NewService(st)})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL, st
}

// runCLI invokes the built binary with args and returns combined output.
func runCLI(t *testing.T, bin, stateDir, endpoint string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--endpoint", endpoint, "--state", stateDir}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Stdin = strings.NewReader("cli-test-password-123\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestCLIAdminInitLoginNodeForward covers the M1 CLI path end to end:
// admin init -> login -> node create -> token -> forward create/list/delete.
func TestCLIAdminInitLoginNodeForward(t *testing.T) {
	bin := buildCLI(t)
	endpoint, st := startAPIServer(t)
	stateDir := t.TempDir()

	// admin init (the CLI generates a password and shows it once).
	out, err := runCLI(t, bin, stateDir, endpoint, "admin", "init")
	if err != nil {
		t.Fatalf("admin init failed: %v (%s)", err, out)
	}
	if !strings.Contains(out, "One-time password") {
		t.Fatalf("admin init did not show the one-time password: %s", out)
	}

	// login with the generated password (parse it from the output).
	var password string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 8 && line != "" &&
			!strings.Contains(line, "admin") && !strings.Contains(line, "password") &&
			!strings.Contains(line, "created") && !strings.Contains(line, "One-time") {
			password = line
			break
		}
	}
	if password == "" {
		t.Fatalf("could not extract generated password from %s", out)
	}
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runCLI(t, bin, stateDir, endpoint, "login", "--username", "admin", "--password-file", pwFile)
	if err != nil || !strings.Contains(out, "logged in") {
		t.Fatalf("login failed: %v (%s)", err, out)
	}

	// node create.
	out, err = runCLI(t, bin, stateDir, endpoint, "node", "create", "--name", "node-a")
	if err != nil {
		t.Fatalf("node create failed: %v (%s)", err, out)
	}
	var node struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &node); err != nil || node.ID == "" {
		t.Fatalf("node create output not JSON: %s", out)
	}

	// node token.
	out, err = runCLI(t, bin, stateDir, endpoint, "node", "token", node.ID)
	if err != nil || !strings.Contains(out, "One-time enrollment token") {
		t.Fatalf("node token failed: %v (%s)", err, out)
	}

	// forward create (direct-v4).
	out, err = runCLI(t, bin, stateDir, endpoint, "forward", "create",
		"--node", node.ID, "--name", "web", "--protocol", "tcp",
		"--target", "10.0.0.5:8080", "--strategy", "direct-v4")
	if err != nil {
		t.Fatalf("forward create failed: %v (%s)", err, out)
	}
	var fwd struct {
		ID   string `json:"id"`
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal([]byte(out), &fwd); err != nil || fwd.ID == "" || fwd.ETag == "" {
		t.Fatalf("forward create output not JSON: %s", out)
	}

	// forward list contains the forward.
	out, err = runCLI(t, bin, stateDir, endpoint, "forward", "list")
	if err != nil || !strings.Contains(out, fwd.ID) {
		t.Fatalf("forward list failed: %v (%s)", err, out)
	}

	// forward delete (online).
	out, err = runCLI(t, bin, stateDir, endpoint, "forward", "delete", fwd.ID)
	if err != nil || !strings.Contains(out, "delete accepted") {
		t.Fatalf("forward delete failed: %v (%s)", err, out)
	}

	// The session cookie file must be 0600.
	info, err := os.Stat(filepath.Join(stateDir, "session"))
	if err != nil {
		t.Fatalf("session file missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("session file mode = %v, want 0600", info.Mode().Perm())
	}
	_ = st
}

// TestCLIUnauthenticatedFails covers Story 4 RED: an operation without a
// session is refused.
func TestCLIUnauthenticatedFails(t *testing.T) {
	bin := buildCLI(t)
	endpoint, _ := startAPIServer(t)
	stateDir := t.TempDir()

	out, err := runCLI(t, bin, stateDir, endpoint, "node", "list")
	if err == nil {
		t.Fatalf("node list without login succeeded: %s", out)
	}
	if !strings.Contains(out, "401") && !strings.Contains(out, "UNAUTHENTICATED") {
		t.Fatalf("unexpected error output: %s", out)
	}
}
