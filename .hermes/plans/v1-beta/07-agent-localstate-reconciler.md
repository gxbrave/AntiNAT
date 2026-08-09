# P07 — Agent bbolt State and Reconciler Foundation Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement versioned local state, durable inbox/outbox, AppliedForwardState, tombstones, terminal marker, and isolated actor/reconcile interfaces without network-specific forwarding.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P05 integrated.

**Wave:** W4B parallel with P06

**Preferred model profile:** Go distributed-state/concurrency model

---

## Owned files

- Create/own: `internal/agent/localstate/**`, `internal/agent/reconcile/{reconciler.go,actor.go,desired.go,operation.go}`
- Create/own localstate/reconcile tests and crash harness

## Ownership transfer / integration notes

P10 may add activation/probe files and modify declared extension points after P07 integration. P14 later owns deletion/decommission/recovery extensions. Core invariants remain protected by tests.

## Explicit non-goals

No actual sockets, STUN, target proxy, WebSocket transport, Controller DB or UI.

## Stories

### Story 1: bbolt schema and migration
- RED: unknown future schema, corrupt store, lock contention and failed migration fail closed.
- GREEN: versioned buckets and atomic transactions.

### Story 2: received desired vs applied state
- RED: one Forward apply failure must retain old applied state while sibling advances.
- GREEN: per-resource apply result and PARTIAL semantics.

### Story 3: durable inbox/outbox
- RED: duplicate message/type/hash, old revision, result resend and receipt GC cases.
- GREEN: semantic operation and delivery journals.

### Story 4: Forward tombstones
- RED: deletion intent then crash/old snapshot/controller rollback never resurrects Forward.
- GREEN: tombstone-before-stop contract hooks and GC preconditions.

### Story 5: terminal marker/latch
- RED: marker write races with desired apply; no actor may start after latch.
- GREEN: fsync temp+rename+parent sync and DECOMMISSIONING/DECOMMISSIONED load behavior.

### Story 6: actor isolation
- RED: one actor panic/failure cannot stop sibling or control loop.
- GREEN: bounded lifecycle interface and supervisor result reporting.

## Required verification

```bash
go test ./internal/agent/localstate ./internal/agent/reconcile -race -count=10
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P07-agent-localstate` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P07.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
