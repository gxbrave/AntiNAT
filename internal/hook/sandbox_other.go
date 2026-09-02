//go:build !linux

package hook

import (
	"context"
	"errors"
)

// probeSandboxPlatform on non-Linux platforms fails closed: the JS capability
// is webhook-only (P03 verdict: Windows isolated JS is NO_GO; Job Object alone
// is insufficient).
func probeSandboxPlatform(executable string) SandboxResult {
	return unsupportedSandbox("OS isolation minimum gate is not implemented on this platform (webhook-only)")
}

// runSandboxedScript never runs on non-Linux platforms.
func runSandboxedScript(ctx context.Context, executable string, script, request []byte, limits Limits) ([]byte, error) {
	return nil, ErrRunnerUnsupported
}

// ChildSelfCheck on non-Linux platforms always fails closed (the runner
// capability is unsupported; a native Windows restricted-token/AppContainer
// runner is out of v1 scope per P03).
func ChildSelfCheck(action string, uid, gid int) error {
	return errors.New("hook: isolated JS runner is unsupported on this platform")
}

// ChildEntry fails closed on non-Linux platforms.
func ChildEntry(action string) error {
	return ErrRunnerUnsupported
}
