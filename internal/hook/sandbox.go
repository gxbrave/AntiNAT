package hook

import (
	"context"
	"errors"
	"sync"
)

// GateResult is one OS-isolation gate's outcome. Detail is honest and
// limit-specific (SIGXCPU/OOM observables are never replaced by a generic
// SIGKILL claim).
type GateResult struct {
	Pass   bool
	Detail string
}

// SandboxResult is the full OS-isolation capability probe. Supported is true
// only when every minimum gate passes; on any missing gate the capability
// degrades to webhook-only (never a skipped PASS).
type SandboxResult struct {
	Supported bool
	Fallback  string
	Gates     map[string]GateResult
}

// requiredUnixGates are the Linux minimum-gate names (v0.8 §8.1).
var requiredUnixGates = []string{
	"dedicated_uid",
	"sanitized_env",
	"no_inherited_fd",
	"no_new_privileges",
	"network_namespace",
	"mount_namespace_empty_root",
	"seccomp_socket_connect",
	"seccomp_exec",
	"file_denied",
	"cpu_bounded",
	"allocation_bounded",
}

func unsupportedSandbox(detail string) SandboxResult {
	res := SandboxResult{Supported: false, Fallback: "webhook-only", Gates: map[string]GateResult{}}
	for _, name := range requiredUnixGates {
		res.Gates[name] = GateResult{Detail: detail}
	}
	return res
}

// ProbeSandbox runs the OS-isolation gate on executable (the
// cmd/antinat-hook-runner child). On platforms without the minimum gate
// (Windows, or Linux without root/identity/namespace/seccomp) it fails closed.
func ProbeSandbox(executable string) SandboxResult {
	return probeSandboxPlatform(executable)
}

// ErrRunnerUnsupported is returned when a script delivery needs the isolated
// JS runner but the platform sandbox minimum gate is not present (webhook-only
// fallback; never a silent PASS).
var ErrRunnerUnsupported = errors.New("hook: isolated JS runner is unsupported on this platform")

// RuntimeRunner is the production script runner that executes user scripts in
// the OS-isolated child (cmd/antinat-hook-runner) when the minimum gate is
// present, and fails closed otherwise.
type RuntimeRunner struct {
	// Exe is the path to the antinat-hook-runner child binary
	// ("" resolves to "antinat-hook-runner" on PATH).
	Exe    string
	Limits Limits

	// probeMu guards probed/probedDone/forceUnsup so Capability (and therefore
	// Run, via Capability) is safe under concurrent use (P3-3). Without it the
	// lazy probe state was a latent data race, safe only because the dispatcher
	// is single-goroutine today; a concurrent acquired/acquired probe could read
	// a partially-written SandboxResult.
	probeMu    sync.Mutex
	probed     SandboxResult
	probedDone bool
	forceUnsup bool
}

// NewRuntimeRunner builds the OS-isolated script runner.
func NewRuntimeRunner(exe string, limits Limits) *RuntimeRunner {
	if exe == "" {
		exe = "antinat-hook-runner"
	}
	return &RuntimeRunner{Exe: exe, Limits: limits}
}

// SetUnsupported forces the runner into webhook-only (tests). It takes the
// probe lock so it is race-free against concurrent Capability() calls.
func (r *RuntimeRunner) SetUnsupported() {
	if r == nil {
		return
	}
	r.probeMu.Lock()
	defer r.probeMu.Unlock()
	r.forceUnsup = true
	r.probedDone = true
	r.probed = unsupportedSandbox("force unsupported (test fixture)")
}

// Capability reports "isolated-js" when the platform gate passes, else
// "unsupported". It never blocks; the first Run drives the probe. The probe
// state is guarded so concurrent Capability()/Run() calls cannot race (P3-3);
// only one goroutine runs the (expensive) probe and the others wait on the
// mutex, then all observe the same settled result.
func (r *RuntimeRunner) Capability() string {
	if r == nil {
		return "unsupported"
	}
	r.probeMu.Lock()
	defer r.probeMu.Unlock()
	if r.forceUnsup {
		return "unsupported"
	}
	if r.probedDone {
		if r.probed.Supported {
			return "isolated-js"
		}
		return "unsupported"
	}
	// Probe lazily (root + dedicated identity required on Linux).
	res := ProbeSandbox(r.Exe)
	r.probed = res
	r.probedDone = true
	if res.Supported {
		return "isolated-js"
	}
	return "unsupported"
}

// Run executes one script in the OS-isolated child and returns the contribution
// envelope bytes. It fails closed (ErrRunnerUnsupported) when the gate is not
// present.
func (r *RuntimeRunner) Run(ctx context.Context, script []byte, request []byte, limits Limits) ([]byte, error) {
	if r == nil {
		return nil, ErrRunnerUnsupported
	}
	if r.Capability() != "isolated-js" {
		return nil, ErrRunnerUnsupported
	}
	return runSandboxedScript(ctx, r.Exe, script, request, limits)
}

// RunEnvelope satisfies the ScriptRunner interface used by the delivery
// preparer (identical gate: fail closed unless the OS-isolation min gate is
// present).
func (r *RuntimeRunner) RunEnvelope(ctx context.Context, script []byte, request []byte, limits Limits) ([]byte, error) {
	return r.Run(ctx, script, request, limits)
}
