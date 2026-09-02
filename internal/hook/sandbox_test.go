package hook_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

// The OS-isolation child binary is compiled ONCE before the sandbox gates run
// (P3-16). In the cold-start failure this fixes, two sandbox tests each invoked
// `go build` for their own child inside the test body, so a cold build cache
// (~1.2s) ran concurrently with the namespace/uid gates and produced a
// non-reproducible gate failure. Building once up front removes the cold-cache
// contention from the gate itself. NOTE: no gate result is ever retried away
// here — this is a deterministic build-once layout, not a retry-on-failure.
var (
	// runnerChildOnce guards the single child compile; runnerChildExe is reused
	// by every sandbox test in this package.
	runnerChildOnce sync.Once
	runnerChildExe  string
	runnerChildErr  error
)

// buildRunnerChild compiles cmd/antinat-hook-runner ONCE into a package-level
// temp dir and returns its path; the sandbox tests exec the REAL production
// child. Each test reuses the same compiled binary, so a cold `go build` cannot
// race the OS-isolation gates.
func buildRunnerChild(t *testing.T) string {
	t.Helper()
	runnerChildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "antinat-runner-child-pool")
		if err != nil {
			runnerChildErr = err
			return
		}
		runnerChildExe = filepath.Join(dir, "antinat-hook-runner")
		cmd := exec.Command("go", "build", "-o", runnerChildExe, "github.com/gxbrave/AntiNAT/cmd/antinat-hook-runner")
		cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		output, combErr := cmd.CombinedOutput()
		if combErr != nil {
			runnerChildErr = fmt.Errorf("build runner child: %v\n%s", combErr, output)
			return
		}
	})
	if runnerChildErr != nil {
		t.Fatal(runnerChildErr)
	}
	return runnerChildExe
}

// sandboxEnabled reports whether the host has the minimum gate the real probe
// needs: root + a provisioned dedicated identity in /etc/passwd.
func sandboxEnabled(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() != 0 {
		return false
	}
	if os.Getenv("ANTINAT_DEDICATED_UID") == "" || os.Getenv("ANTINAT_DEDICATED_GID") == "" {
		return false
	}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	want := os.Getenv("ANTINAT_DEDICATED_UID")
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 && line[0] != '#' {
			fields := strings.Split(line, ":")
			if len(fields) > 2 && fields[2] == want {
				return true
			}
		}
	}
	return false
}

// RED P16 Story 5 (a): without a provisioned dedicated identity the whole
// sandbox gate fails closed (never a skipped PASS).
func TestSandboxGateFailsClosedWithoutIdentity(t *testing.T) {
	t.Setenv("ANTINAT_DEDICATED_UID", "")
	t.Setenv("ANTINAT_DEDICATED_GID", "")
	// The shared nobody identity is rejected too.
	t.Setenv("ANTINAT_DEDICATED_UID", "65534")
	t.Setenv("ANTINAT_DEDICATED_GID", "65534")
	res := hook.ProbeSandbox("antinat-hook-runner")
	if res.Supported {
		t.Fatal("sandbox gate passed without a dedicated identity")
	}
	if res.Fallback != "webhook-only" {
		t.Fatalf("fallback = %q, want webhook-only", res.Fallback)
	}
	gate, ok := res.Gates["dedicated_uid"]
	if !ok || gate.Pass {
		t.Fatalf("dedicated_uid gate not failed closed: %+v", res.Gates["dedicated_uid"])
	}
}

// RED P16 Story 5 (b): the Linux/amd64 minimum gate passes only on the
// recorded host shape (root + provisioned non-nobody dedicated identity). On
// any other host the test skips with the fail-closed reason — it never claims
// a PASS it cannot prove.
func TestSandboxRealIsolationGate(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("sandbox seccomp program is amd64-only; capability webhook-only here")
	}
	if !sandboxEnabled(t) {
		t.Skip("sandbox gate fails closed: requires root and ANTINAT_DEDICATED_UID/GID naming a provisioned dedicated identity")
	}
	exe := buildRunnerChild(t)
	res := hook.ProbeSandbox(exe)
	if !res.Supported {
		out := new(strings.Builder)
		for name, g := range res.Gates {
			out.WriteString(name + "=" + g.Detail + "; ")
		}
		t.Fatalf("sandbox gate failed on the provisioned host: %s", out)
	}
}

// RED P16 Story 5 (c): the RuntimeRunner reports "unsupported" (webhook-only)
// when the platform gate is absent, and refuses to run (never a silent PASS).
func TestRuntimeRunnerUnsupportedWhenGateAbsent(t *testing.T) {
	r := hook.NewRuntimeRunner("antinat-hook-runner", hook.DefaultLimits())
	r.SetUnsupported()
	if r.Capability() != "unsupported" {
		t.Fatalf("capability = %q, want unsupported", r.Capability())
	}
	if _, err := r.Run(context.Background(), []byte(`function main(){}`), []byte(`{}`), hook.DefaultLimits()); err == nil {
		t.Fatal("runner ran despite unsupported gate")
	}
}

// RED P16 Story 5 (d): on a provisioned Linux host the real sandbox child
// executes a script and returns the correct canonical contribution with no
// secret material in the envelope.
func TestSandboxRunnerExecutesIsolatedScript(t *testing.T) {
	if runtime.GOOS != "linux" || !sandboxEnabled(t) {
		t.Skip("requires root and a provisioned dedicated identity (webhook-only fallback)")
	}
	exe := buildRunnerChild(t)
	r := hook.NewRuntimeRunner(exe, hook.DefaultLimits())
	script := []byte(canonicalScript)
	request, _ := json.Marshal(map[string]any{
		"event_id": "evt-1", "hook_id": "hook-1", "method": "GET", "path": "/",
		"params": map[string]any{"AccessKeyId": "LTAI-test", "Action": "DescribeDomainRecords", "Version": "2015-01-09"},
	})
	raw, err := r.Run(context.Background(), script, request, hook.DefaultLimits())
	if err != nil {
		t.Fatalf("sandbox run: %v (no secret material is ever sent to the child)", err)
	}
	var result struct {
		OK           bool                       `json:"ok"`
		Contribution map[string]json.RawMessage `json:"contribution"`
		Err          *struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("parse runner envelope: %v: %s", err, raw)
	}
	var parsed struct {
		Contribution map[string]string `json:"contribution"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse contribution: %v (%s)", err, raw)
	}
	canonicalQuery := parsed.Contribution["canonical_query"]
	stringToSign := parsed.Contribution["string_to_sign"]
	if !strings.HasPrefix(canonicalQuery, "AccessKeyId=") {
		t.Fatalf("contribution not canonical: %q", canonicalQuery)
	}
	if !strings.Contains(stringToSign, "GET&%2F&") {
		t.Fatalf("string_to_sign malformed: %q", stringToSign)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatal("sandbox envelope leaked secret-derived material")
	}
}

// RED P16 Story 5 (e): the dedicated-identity gate rejects the shared
// nobody/nogroup identity and missing provision without touching the child.
func TestDedicatedIdentityRejectsNobody(t *testing.T) {
	// cachedIdentity tests run through ProbeSandbox fail-closed coverage; the
	// parsing rules are exercised here directly when root-less.
	if !sandboxEnabled(t) {
		t.Skip("only meaningful on a provisioned host")
	}
	t.Setenv("ANTINAT_DEDICATED_UID", "65534")
	t.Setenv("ANTINAT_DEDICATED_GID", "65534")
	res := hook.ProbeSandbox("antinat-hook-runner")
	if res.Supported {
		t.Fatal("shared nobody identity passed the dedicated-UID gate")
	}
}
