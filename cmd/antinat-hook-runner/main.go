// antinat-hook-runner is the OS-isolated JavaScript runner child (P16 Story 5).
//
// The controller parent execs this binary inside a fresh network+mount
// namespace with an empty chroot, a dedicated non-nobody UID/GID, NoNewPrivileges,
// an amd64 seccomp filter and bounded RLIMITs. The child resolves its dedicated
// identity, isolates itself, and either:
//
//   - `-selfcheck <action>` runs one gate self-check (inspect/env/fd/socket/
//     exec/file/loop/allocation) that the parent's ProbeSandbox interprets, or
//   - `-selfcheck run` reads a strict envelope {script_sha256, script, request}
//     on stdin, verifies the pinned hash, executes the script with the bounded
//     interpreter, and writes the result envelope to stdout.
//
// The child NEVER receives secret material: the envelope holds only the script
// and the request-description (v0.8 §8.2/§8.3), and the parent caps stdout at
// 64 KiB.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

func main() {
	action := flag.String("selfcheck", "", "run the sandbox self-check/run action inside the OS jail")
	flag.Parse()
	if err := hook.ChildEntry(*action); err != nil {
		fmt.Fprintln(os.Stderr, "antinat-hook-runner:", err)
		os.Exit(1)
	}
}
