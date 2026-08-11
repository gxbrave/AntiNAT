//go:build linux

package sandbox

import (
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

func TestBoundedActionAcceptsOnlyExpectedTermination(t *testing.T) {
	if pass, _ := boundedActionPassed("allocation", nil, syscall.WaitStatus(2<<8), "runtime: out of memory"); !pass {
		t.Fatal("runtime out-of-memory termination was not accepted")
	}
	if pass, _ := boundedActionPassed("loop", nil, syscall.WaitStatus(syscall.SIGKILL), ""); !pass {
		t.Fatal("SIGKILL CPU-limit termination was not accepted")
	}
}
