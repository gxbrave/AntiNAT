# AntiNAT

AntiNAT is a Go-based Controller + Agent project for evidence-backed IPv4 endpoint publication and forwarding. The Controller owns management state, health, and the authenticated control plane; an Agent owns local sockets, traversal attempts, and user traffic. The Controller never relays user payloads.

## Current development status

The authoritative development baseline is `a3626376e707ffbdcdc142269dc2db6b03a2479c` on `integration/v1-beta` (also checked out as `integration/P12-staging`). P01–P12 are integrated. P13 at `8f56e973722ff378881806c11e658ee8c9d96136` is reviewed but not integrated; P14–P19 are unstarted. This is not a v1.0-beta release.

P10 composed working Controller/Agent application paths and a local Linux direct-v4 walking skeleton. P12 added reviewed STUN/gateway traversal libraries, strategy, detection/profile, mapping lifecycle, and Linux netns lab coverage, with M2 recorded `PASS_WITH_DECLARED_LIMITS`.

Important qualification: the production Agent composition does not yet instantiate P12's traversal `Manager` or `Detector`, register PCP/NAT-PMP/UPnP adapters, or provide the durable bbolt `JournalStore` adapter. `MemoryJournal` is an in-memory test/lab implementation, not a production store. Therefore P12 gateway traversal is accepted at library/lab scope but is not yet reachable as a production Forward path through `antinat-agent`.

See:

- `docs/development/CURRENT_STATE.md` — authoritative plan, milestone, limitation, stop-condition, and next-decision status;
- `docs/development/WORKSPACE_INVENTORY.md` — repositories, worktrees, preservation, and cleanup state;
- `HANDOFF/NEXT_AI.md` — operational handoff;
- `HANDOFF/CLEANUP_LEDGER.md` — exact pending cleanup allowlist and deferred set.

Historical August handoff/project-plan documents in the preserved workspace remain historical snapshots and are not current-status authority.

## Scope and claims

The v1.0-beta boundary is frozen in:

- `docs/v1-scope-contract.md` — executable product boundary and truth rules;
- `docs/requirements-traceability.md` — mapping from `antinat.txt` to v1 decisions;
- `docs/support-matrix.md` — `ga`, `beta`, `experimental`, `build-only`, and `unsupported` release statuses;
- `docs/adr/0001` through `docs/adr/0004` — provenance, scope, verification, and reproducibility decisions.

A candidate endpoint is never described as globally reachable merely because a local socket was bound, a gateway mapping succeeded, or STUN returned a mapping. Only a matching authenticated probe from a named independent vantage can produce `OPEN_FROM_VANTAGE`. Local, loopback, netns, fake-server, and cross-build results retain their actual evidence level.

No independent public-WAN, real CPE/router, or native Windows runtime evidence is claimed for the currently integrated traversal paths. Cross-builds are compile evidence only. Installer/platform completion and exact release-artifact evidence remain future P18/P19 work. `govulncheck` was unavailable in recorded integration gates and is not claimed as PASS.

Natter is listed in `antinat.txt` as an inspiration for networking principles. AntiNAT is a clean-room implementation: no Natter source, GPL-3.0 code, or copied implementation is included. AntiNAT source is distributed under the Apache License 2.0 in `LICENSE`.

## Build and verification

The approved module path is `github.com/gxbrave/AntiNAT`. Historical CI validated the project toolchain pin recorded by project governance; use the repository's current Go/toolchain declarations and record the actual environment for new evidence.

```bash
make check
make build
make verify-evidence
./bin/antinat-controller version
./bin/antinat-agent version
```

Some cumulative sandbox tests require the documented dedicated identity:

```bash
ANTINAT_DEDICATED_UID=12001 \
ANTINAT_DEDICATED_GID=12001 \
GOWORK=off make check
```

Build metadata can be injected with `make build VERSION=... COMMIT=... DATE=...`; no secrets belong in those values. Generated `bin/` outputs are ignored and are not release artifacts. Exact release-digest validation belongs to P19.

## Development rules

- Follow strict RED -> GREEN -> REFACTOR for behavioral work and preserve the failing-test evidence.
- Consume dependencies only from integrated commits; keep implementation work isolated by branch/worktree.
- Implementers do not approve their own work. Required fresh specification, quality/security, and specialist reviews must pass before integration.
- Frozen-contract conflicts require a contract-change handoff and approval; do not silently reinterpret contracts.
- Do not claim Windows, arm64, Docker, traversal, WAN, installer, platform, or release capability beyond the support matrix and exact evidence.
- Do not integrate P13, begin P14, remove worktrees, or perform destructive cleanup merely because this README records the current state. Follow `HANDOFF/NEXT_AI.md` and the exact authorization boundary.
- CI uses read-only permissions, pinned action SHAs, fixed job timeouts, and separate test lanes. Fork pull requests must not receive secrets or privileged execution.
