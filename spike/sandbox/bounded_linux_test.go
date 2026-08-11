//go:build linux

package sandbox

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestBoundedActionRejectsOrdinarySetupFailure(t *testing.T) {
	status := syscall.WaitStatus(1 << 8)
	if pass, _ := boundedActionPassed("allocation", nil, status, "setup failed"); pass {
		t.Fatal("ordinary allocation helper exit was accepted as a resource-limit PASS")
	}
	if pass, _ := boundedActionPassed("loop", nil, status, "setup failed"); pass {
		t.Fatal("ordinary loop helper exit was accepted as a resource-limit PASS")
	}
}

func TestBoundedActionRejectsGenericSIGKILLForCPULimit(t *testing.T) {
	// A bare SIGKILL is not proof of the configured RLIMIT_CPU bound: an OOM
	// killer, an external kill, or seccomp kill would also produce it. Only a
	// SIGXCPU from the configured soft CPU limit may be accepted.
	if pass, _ := boundedActionPassed("loop", nil, syscall.WaitStatus(syscall.SIGKILL), ""); pass {
		t.Fatal("generic SIGKILL was accepted as RLIMIT_CPU proof; want fail closed")
	}
}

func TestBoundedActionRejectsGenericSIGKILLForAllocation(t *testing.T) {
	// A bare SIGKILL with no observable address-space failure message must not
	// be accepted as allocation-bound proof.
	if pass, _ := boundedActionPassed("allocation", nil, syscall.WaitStatus(syscall.SIGKILL), ""); pass {
		t.Fatal("generic SIGKILL was accepted as allocation-bound proof; want fail closed")
	}
}

func TestBoundedActionAcceptsSIGXCPUForCPULimit(t *testing.T) {
	// The configured soft RLIMIT_CPU terminates the busy loop with SIGXCPU;
	// that signal is the observable, limit-specific termination.
	if pass, reason := boundedActionPassed("loop", nil, syscall.WaitStatus(syscall.SIGXCPU), ""); !pass {
		t.Fatalf("SIGXCPU RLIMIT_CPU termination was not accepted: %s", reason)
	}
	// A generic SIGKILL accompanied by the child's SIGXCPU marker and its
	// distinctive exit code is the Go-runtime-compatible observable proof.
	if pass, _ := boundedActionPassed("loop", nil, syscall.WaitStatus(42<<8), "sandbox: received SIGXCPU from the configured RLIMIT_CPU soft limit"); !pass {
		t.Fatal("SIGXCPU marker with exit code 42 was not accepted as RLIMIT_CPU proof")
	}
	// The marker without the distinctive exit code must not pass.
	if pass, _ := boundedActionPassed("loop", nil, syscall.WaitStatus(1<<8), "sandbox: received SIGXCPU from the configured RLIMIT_CPU soft limit"); pass {
		t.Fatal("SIGXCPU marker with an ordinary exit code was accepted; want fail closed")
	}
	// The distinctive exit code without the marker must not pass.
	if pass, _ := boundedActionPassed("loop", nil, syscall.WaitStatus(42<<8), ""); pass {
		t.Fatal("exit code 42 without the SIGXCPU marker was accepted; want fail closed")
	}
}

func TestBoundedActionAcceptsOnlyOOMTerminationForAllocation(t *testing.T) {
	// The address-space limit is proven by the runtime's observable
	// out-of-memory message on a normal exit, not by an arbitrary signal.
	if pass, _ := boundedActionPassed("allocation", nil, syscall.WaitStatus(2<<8), "runtime: out of memory"); !pass {
		t.Fatal("runtime out-of-memory termination was not accepted")
	}
	if pass, _ := boundedActionPassed("allocation", nil, syscall.WaitStatus(2<<8), "cannot allocate memory"); !pass {
		t.Fatal("cannot-allocate-memory termination was not accepted")
	}
	if pass, _ := boundedActionPassed("allocation", nil, syscall.WaitStatus(2<<8), "some other fatal error"); pass {
		t.Fatal("non-memory fatal exit was accepted as allocation-bound proof")
	}
}

func TestBoundedActionRejectsOuterDeadlineExpiry(t *testing.T) {
	// If the outer watchdog deadline expired before a proven resource-limit
	// termination, the gate must fail closed rather than guess.
	status := syscall.WaitStatus(1 << 8)
	if pass, _ := boundedActionPassed("loop", context.DeadlineExceeded, status, ""); pass {
		t.Fatal("outer-deadline expiry was accepted as a resource-limit PASS")
	}
	if pass, _ := boundedActionPassed("allocation", context.DeadlineExceeded, status, ""); pass {
		t.Fatal("outer-deadline expiry was accepted as a resource-limit PASS")
	}
}

// TestBoundedActionRealCPULimitTermination exercises the real bounded path:
// the child sets the configured RLIMIT_CPU soft bound and the busy loop is
// terminated by SIGXCPU. This is the end-to-end proof the synthetic unit cases
// cannot provide. When root or a provisioned identity is unavailable the gate
// must fail closed (the capability is unsupported), never silently pass.
func TestBoundedActionRealCPULimitTermination(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Setenv("ANTINAT_DEDICATED_UID", "")
		t.Setenv("ANTINAT_DEDICATED_GID", "")
	}
	gate := runAction(os.Args[0], "loop")
	if gate.Pass {
		if !strings.Contains(gate.Detail, "SIGXCPU") {
			t.Fatalf("real RLIMIT_CPU gate passed without SIGXCPU proof: %+v", gate)
		}
		return
	}
	if strings.Contains(gate.Detail, "dedicated identity required") {
		t.Skipf("no provisioned dedicated identity on this host; gate fails closed: %s", gate.Detail)
	}
	t.Fatalf("real RLIMIT_CPU gate failed: %+v", gate)
}
