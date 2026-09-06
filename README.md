# AntiNAT

AntiNAT is a Go-based Controller + Agent project for evidence-backed IPv4 endpoint publication and forwarding. The Controller owns management state, health, and the authenticated control plane; an Agent owns local sockets, traversal attempts, and user traffic. The Controller never relays user payloads.

## Current development status

The authoritative integrated baseline is `622f98b8e3958a14094c1fad5cd775f3c93ccdb1` on `integration/v1-beta`; P01-P18 are integrated with the limits recorded in their handoffs. This branch contains the P19 release-candidate tooling and evidence verifier. The release target is Debian/Ubuntu Linux only; Windows remains build-only until a native test host is available.

P10 composed working Controller/Agent application paths and a local Linux direct-v4 walking skeleton. P12/P12W added reviewed STUN/gateway traversal libraries and production composition, while P13–P18 added the remaining lifecycle, API, hook, UI, installer, service, and platform packaging work. The P19 runner builds the candidate once and binds every gate to the exact manifest digest.

Important qualification: no independent public-WAN, real CPE/router, native Windows, native OpenRC, registry OCI digest, or 24-hour soak evidence is available for this candidate run. Native Debian 12 ARM64 Controller/Agent and Debian 12 amd64 plus Ubuntu 22.04 amd64 startup/control checks are recorded, but they do not promote direct-v4 reachability on a host without a global IPv4 source. Browser coverage and `govulncheck` run in the refreshed release lane; those results do not replace WAN, registry, or soak evidence. The remaining gaps keep the candidate at `SUPPORTED_WITH_LIMITS` until the protected release inputs are supplied.

See:

- `docs/development/CURRENT_STATE.md` — authoritative plan, milestone, limitation, stop-condition, and next-decision status;
- `docs/development/WORKSPACE_INVENTORY.md` — repositories, worktrees, preservation, and cleanup state;
- `HANDOFF/NEXT_AI.md` — operational handoff;
- `HANDOFF/CLEANUP_LEDGER.md` — exact pending cleanup allowlist and deferred set.

Historical August handoff/project-plan documents in the preserved workspace remain historical snapshots and are not current-status authority.

## Debian/Ubuntu install

The first release targets Debian 12 and Ubuntu 22.04/24.04 on Linux amd64 and arm64. The bootstrap script fetches the signed release manifest and architecture-specific artifacts; it does not use an unsigned checksum as a trust anchor.

The public bootstrap command is:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh) install --controller-endpoint https://controller.example.com:3111
```

The generated deployment command supplies `ANTINAT_NODE_ID` and `ANTINAT_CONTROLLER_PIN` separately and reads the one-time enrollment token from the installer TTY or a protected `--token-file`/`--token-fd`. Do not put the token in the shell command or in a URL.

Windows binaries and the PowerShell installer are build-only artifacts for this beta. They are not a native Windows support claim and have not been validated on a Windows host.

## Scope and claims

The v1.0-beta boundary is frozen in:

- `docs/v1-scope-contract.md` — executable product boundary and truth rules;
- `docs/requirements-traceability.md` — mapping from `antinat.txt` to v1 decisions;
- `docs/support-matrix.md` — `ga`, `beta`, `experimental`, `build-only`, and `unsupported` release statuses;
- `docs/adr/0001` through `docs/adr/0004` — provenance, scope, verification, and reproducibility decisions.

A candidate endpoint is never described as globally reachable merely because a local socket was bound, a gateway mapping succeeded, or STUN returned a mapping. Only a matching authenticated probe from a named independent vantage can produce `OPEN_FROM_VANTAGE`. Local, loopback, netns, fake-server, and cross-build results retain their actual evidence level.

No independent public-WAN, real CPE/router, or native Windows runtime evidence is claimed for the currently integrated traversal paths. Cross-builds are compile evidence only. P18 installer/platform evidence remains bounded by its documented host and registry limits. The refreshed P19 lane runs the pinned browser suite and `govulncheck` on Go 1.26.6; these checks do not replace the unavailable external gates.

Natter is listed in `antinat.txt` as an inspiration for networking principles. AntiNAT is a clean-room implementation: no Natter source, GPL-3.0 code, or copied implementation is included. AntiNAT source is distributed under the Apache License 2.0 in `LICENSE`.

## Build and verification

The approved module path is `github.com/gxbrave/AntiNAT`. Historical CI validated the project toolchain pin recorded by project governance; use the repository's current Go/toolchain declarations and record the actual environment for new evidence.

```bash
make check
make build
make verify-evidence
./bin/antinat-controller version
./bin/antinat-agent version
./scripts/run-beta-gates.sh --artifacts ./dist --evidence ./artifacts/evidence
go run ./scripts/verify-release-evidence.go ./artifacts/evidence
```

Some cumulative sandbox tests require the documented dedicated identity:

```bash
ANTINAT_DEDICATED_UID=12001 \
ANTINAT_DEDICATED_GID=12001 \
GOWORK=off make check
```

Build metadata can be injected with `make build VERSION=... COMMIT=... DATE=...`; no secrets belong in those values. Generated `bin/` outputs are ignored and are not release artifacts. The beta runner requires a clean Linux amd64 checkout and never tags, pushes, or publishes a candidate.

## Development rules

- Follow strict RED -> GREEN -> REFACTOR for behavioral work and preserve the failing-test evidence.
- Consume dependencies only from integrated commits; keep implementation work isolated by branch/worktree.
- Implementers do not approve their own work. Required fresh specification, quality/security, and specialist reviews must pass before integration.
- Frozen-contract conflicts require a contract-change handoff and approval; do not silently reinterpret contracts.
- Do not claim Windows, arm64, Docker, traversal, WAN, installer, platform, or release capability beyond the support matrix and exact evidence.
- Do not integrate P13, begin P14, remove worktrees, or perform destructive cleanup merely because this README records the current state. Follow `HANDOFF/NEXT_AI.md` and the exact authorization boundary.
- CI uses read-only permissions, pinned action SHAs, fixed job timeouts, and separate test lanes. Fork pull requests must not receive secrets or privileged execution.
