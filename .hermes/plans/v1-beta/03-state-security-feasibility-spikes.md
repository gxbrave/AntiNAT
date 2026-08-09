# P03 — State, Storage, Sandbox, and Security Feasibility Spikes Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Validate SQLite/bbolt crash semantics, control delivery phases, key storage, backup behavior, JS runner isolation, and data-path observability before contracts are frozen.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P01 integrated.

**Wave:** W1B parallel with P02

**Preferred model profile:** Security/distributed-systems model with Go storage and OS sandbox expertise

---

## Owned files

- Create/own: `spike/state/**`, `spike/sqlite/**`, `spike/sandbox/**`, `spike/datapath/**`, `spike/windows-identity/**`
- Create/own: `test/evidence/m0/state-security/**`, `docs/evidence/m0-state-security-summary.md`

## Ownership transfer / integration notes

P04 consumes results. Spike code is not production code. Preserve reproducibility manifests.

## Explicit non-goals

No final DB schema, no production key rotation, no UI, no claims based only on cross-build.

## Stories

### Story 1: SQLite driver and backup
- RED: candidate must fail if it needs unintended CGO, cannot cross-build, loses WAL data, or lacks consistent backup.
- GREEN: minimal driver fixtures for migrations, WAL, busy timeout, Backup API/VACUUM INTO.
- VERIFY: Linux/Windows builds, concurrent writes, corruption, full disk, license inventory.

### Story 2: bbolt + terminal marker crash matrix
- RED: kill at intent, marker, side effect, result, ACK, receipt phases.
- GREEN: minimal journal prototype with fsync+rename+parent fsync marker.
- VERIFY: partial apply preserves old LKG; delete/decommission never resurrect; corrupt store fails closed.

### Story 3: Durable control phases and epoch fencing
- RED: two concurrent sessions and stale signed commands must be rejected on both sides.
- GREEN: minimal epoch/inbox/outbox semantic prototype.
- VERIFY: old-epoch ACK resend on new session, duplicate ID conflict, ACK receipt GC.

### Story 4: Hook runner isolation
- RED: malicious fixture attempts socket, file, exec, env, inherited FD, infinite loop, and allocation.
- GREEN: Linux namespace/seccomp fixture and Windows restricted-token/AppContainer feasibility fixture.
- VERIFY: if minimum isolation fails, classify webhook-only; never substitute Job Object alone.

### Story 5: Data-path observability and budgets
- RED: standard io.Copy must not claim exact splice bytes.
- GREEN: compare splice-eligible and buffered paths; reserve pessimistic fallback memory.
- VERIFY: CPU/alloc/RSS baseline and evidence labels only.

### Story 6: Evidence classification
- Validate every evidence JSON and document exact production contract changes/fallbacks.

## Required verification

```bash
go test ./spike/state/... ./spike/sqlite/... ./spike/sandbox/... ./spike/datapath/... -count=1 -v
go run ./scripts/verify-evidence.go ./test/evidence/m0/state-security
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P03-state-security-spikes` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P03.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
