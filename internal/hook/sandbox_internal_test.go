//go:build linux

package hook

import (
	"strings"
	"testing"
)

// RED P16 repair P3-15: the env-isolation gate verifies the child received
// EXACTLY the allowlisted environment — no inherited extras (including any
// secret-named variable), no missing allowlisted keys. A single magic marker
// variable is a tautology; the whole allowlist is the protection.
func TestVerifySandboxEnvExactAllowlist(t *testing.T) {
	base := []string{
		"PATH=/usr/bin:/bin",
		"GOMAXPROCS=2",
		"ANTINAT_SANDBOX_HELPER=1",
		"ANTINAT_SANDBOX_ROOT=/tmp/x",
		"ANTINAT_PARENT_NETNS=net:[1]",
		"ANTINAT_PARENT_MNTNS=mnt:[2]",
		"ANTINAT_DEDICATED_UID=12001",
		"ANTINAT_DEDICATED_GID=12001",
	}
	if err := verifySandboxEnv(base); err != nil {
		t.Fatalf("exact allowlisted env rejected: %v", err)
	}
	// An inherited secret-named variable (the old magic marker or any other)
	// must be rejected — the gate is not keyed on one name.
	for _, kv := range []string{
		"ANTINAT_SANDBOX_SECRET=leaked",
		"AWS_SECRET_ACCESS_KEY=x",
		"MY_HOOK_SECRET=plaintext",
		"HTTP_PROXY=http://internal:8080",
	} {
		if err := verifySandboxEnv(append(append([]string{}, base...), kv)); err == nil {
			t.Fatalf("extra inherited env var %q accepted by the gate", kv)
		}
	}
	// A missing allowlisted key must be rejected.
	for i := range base {
		trunc := append([]string{}, base[:i]...)
		trunc = append(trunc, base[i+1:]...)
		if err := verifySandboxEnv(trunc); err == nil {
			t.Fatalf("missing allowlisted key %q accepted", strings.Split(base[i], "=")[0])
		}
	}
	// The fd gate's documented extra variable is tolerated alone.
	if err := verifySandboxEnv(append(append([]string{}, base...), "ANTINAT_SENTINEL_FD=5")); err != nil {
		t.Fatalf("fd-gate sentinel env rejected: %v", err)
	}
}
