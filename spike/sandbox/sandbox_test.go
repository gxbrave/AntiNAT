//go:build linux

package sandbox

import (
	"os"
	"testing"
)

func TestMaliciousFixturesAreIsolatedOrCapabilityFailsClosed(t *testing.T) {
	result := Probe(os.Args[0])
	required := []string{
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
	failed := 0
	for _, name := range required {
		gate, ok := result.Gates[name]
		if !ok {
			t.Errorf("required gate %q was not reported", name)
			continue
		}
		t.Logf("gate %s: pass=%v detail=%s", name, gate.Pass, gate.Detail)
		if !gate.Pass {
			failed++
		}
	}
	if result.Supported && failed != 0 {
		t.Fatalf("supported with %d failed gates: %+v", failed, result)
	}
	if !result.Supported {
		if failed == 0 {
			t.Fatalf("unsupported without a failed gate: %+v", result)
		}
		if result.Fallback != "webhook-only" {
			t.Fatalf("fallback = %q, want webhook-only", result.Fallback)
		}
	}
}

func TestSandboxChildHelper(t *testing.T) {
	if os.Getenv("ANTINAT_SANDBOX_HELPER") != "1" {
		return
	}
	if err := RunSandboxChild(
		os.Getenv("ANTINAT_SANDBOX_ACTION"),
		os.Getenv("ANTINAT_SANDBOX_ROOT"),
		os.Getenv("ANTINAT_PARENT_NETNS"),
		os.Getenv("ANTINAT_PARENT_MNTNS"),
	); err != nil {
		t.Fatal(err)
	}
}
