//go:build linux && !amd64

package hook

import "errors"

// The production isolated-JS minimum gate is intentionally amd64-only. Keep
// the child entrypoint buildable on other Linux architectures, but fail closed
// if it is invoked directly instead of attempting an amd64 seccomp program.
func installSeccomp() error {
	return errors.New("hook: Linux seccomp runner is supported only on amd64")
}
