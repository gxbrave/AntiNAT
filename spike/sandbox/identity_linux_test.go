//go:build linux

package sandbox

import (
	"os"
	"testing"
)

// Q2 dedicated-identity gate tests. The pre-repair gate labelled the generic
// "inspect" action result as dedicated_uid while always dropping to the shared
// nobody/nogroup identity 65534, so a shared identity passed the dedicated-UID
// minimum gate. These tests require the gate to fail closed unless a
// provisioned, unique, non-nobody service UID/GID is supplied via
// ANTINAT_DEDICATED_UID / ANTINAT_DEDICATED_GID.

func TestDedicatedUIDGateRejectsSharedNobody(t *testing.T) {
	t.Setenv("ANTINAT_DEDICATED_UID", "65534")
	t.Setenv("ANTINAT_DEDICATED_GID", "65534")
	result := Probe(os.Args[0])
	gate, ok := result.Gates["dedicated_uid"]
	if !ok {
		t.Fatal("dedicated_uid gate was not reported")
	}
	if gate.Pass {
		t.Fatalf("dedicated_uid gate passed for the shared nobody identity 65534: %+v", gate)
	}
}

func TestDedicatedUIDGateRequiresProvisionedIdentity(t *testing.T) {
	t.Setenv("ANTINAT_DEDICATED_UID", "")
	t.Setenv("ANTINAT_DEDICATED_GID", "")
	result := Probe(os.Args[0])
	gate, ok := result.Gates["dedicated_uid"]
	if !ok {
		t.Fatal("dedicated_uid gate was not reported")
	}
	if gate.Pass {
		t.Fatalf("dedicated_uid gate passed without a provisioned identity: %+v", gate)
	}
}
