# P18 — Installers, Services, Upgrade/Rollback, Purge, Windows, OpenRC, arm64, and OCI Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement contract-tested Linux/Windows installers, service definitions, artifact trust, transactional upgrade/rollback, safe manifest-driven purge, and evidence-backed platform packaging.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P17, P14, and P08 integrated.

**Wave:** W13

**Preferred model profile:** DevOps/release model with Bash, PowerShell, Windows Service and supply-chain expertise

---

## Owned files

- Create/own: `scripts/{install.sh,libinstall.sh,uninstall.sh,install.ps1,uninstall.ps1}`
- Create/own: `deploy/**`, `internal/install/**`, `Dockerfile*`, `docker/**`, `.github/workflows/platform.yml`
- Create/own platform/installer tests and evidence
- May extend CI with isolated platform jobs; do not weaken P01 policies

## Ownership transfer / integration notes

P19 consumes exact artifacts. Existing installer contract fixtures remain frozen. Production application code changes route back to owner.

## Explicit non-goals

No post-test rebuild, no token in command/history/service/env, no Windows support based only on cross-build, no deleting unowned resources.

## Stories

### Story 1: Reference parser and secret inputs
- RED: every frozen fixture, invalid option, token argv/env/history and noninteractive ACL failure.
- GREEN: common contract parser, TTY/FD/file token path, admin init inputs.

### Story 2: Linux systemd
- RED: fresh install, port conflict, service user/permissions, restart, failed enroll rollback, repeated install.
- GREEN: Controller/Agent/both roles and hardened units.

### Story 3: OpenRC/arm64
- Native environment service/restart/log/cleanup tests; cross-build is build-only evidence.

### Story 4: Windows
- PowerShell quoting/download/signature, service SID/DPAPI-or-ACL, Defender managed/manual rule ownership, restart and native router socket tests.

### Story 5: Upgrade/rollback
- RED: N/N-1 combinations, migration/health failure, disk full/interruption; restore binary+SQLite+bbolt+keys+config.
- GREEN: barrier, backup manifest and atomic health-gated promotion.

### Story 6: Safe purge
- RED: HMAC tamper, symlink/reparse race, path escape, missing manifest, offline nodes, repeated purge.
- GREEN: handle-relative owned-resource deletion and explicit warnings/export.

### Story 7: OCI Linux host-network Beta
- Non-root images, volumes, host networking, health, SBOM/signature and exact image digest E2E.

## Required verification

```bash
go test ./internal/install -race -count=10
./scripts/test-installers.sh
# Native PowerShell/VM/OpenRC/arm64 commands are defined by P04/P18 harness and must emit evidence JSON
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P18-installers-platforms` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P18.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
