# AntiNAT

AntiNAT is a Go-based Controller + Agent project for evidence-backed IPv4
endpoint publication and forwarding. The Controller owns management state,
health, and the authenticated control plane; an Agent owns local sockets,
traversal attempts, and user traffic. The Controller never relays user
payloads.

当前状态：仓库处于 P01 治理与工具链 bootstrap 阶段。此提交只提供范围、
来源、支持矩阵、最小 Go 二进制、证据校验器和 CI 骨架；尚未实现网络监听、
NAT traversal、转发、数据库、UI 或安装器。不要把 bootstrap 二进制当成可用
的 Controller/Agent 服务。

## Scope and claims

The v1.0-beta boundary is frozen in:

- `docs/v1-scope-contract.md` — executable product boundary and truth rules;
- `docs/requirements-traceability.md` — mapping from `antinat.txt` to v1 decisions;
- `docs/support-matrix.md` — `ga`, `beta`, `experimental`, `build-only`, and
  `unsupported` release statuses;
- `docs/adr/0001` through `docs/adr/0004` — provenance, scope, verification,
  and reproducibility decisions.

A candidate endpoint is never described as globally reachable merely because a
local socket was bound or STUN returned a mapping. Only a matching authenticated
probe from a named independent vantage can produce `OPEN_FROM_VANTAGE`; missing
real infrastructure is reported as a capability limitation, not as a pass.

Natter is listed in `antinat.txt` as an inspiration for networking principles.
AntiNAT is a clean-room implementation: no Natter source, GPL-3.0 code, or
copied implementation is included. AntiNAT source is distributed under the
Apache License 2.0 in `LICENSE`.

## Repository bootstrap

The approved module path is `github.com/gxbrave/AntiNAT`. Go 1.26.5 is the
validated toolchain pin for CI.

```bash
make check
make build
make verify-evidence
./bin/antinat-controller version
./bin/antinat-agent version
```

The two binaries intentionally print a bootstrap message and do not bind a
network socket. Build metadata can be injected with `make build VERSION=...
COMMIT=... DATE=...`; no secrets belong in those values.

## Development rules

- Every behavior follows RED -> GREEN -> REFACTOR, with the failing test
  recorded before production code.
- Controller and Agent data-plane code is not part of P01. Later plans must use
  the frozen scope and independently review their evidence.
- Do not claim Windows, arm64, Docker, traversal, zero-copy, or WAN behavior
  from a cross-build or a fake server alone. See the support matrix for the
  required gate for each claim.
- CI uses read-only permissions, pinned action SHAs, fixed job timeouts, and
  separate fast/integration/Windows lanes. Fork pull requests must not receive
  secrets or privileged execution.
