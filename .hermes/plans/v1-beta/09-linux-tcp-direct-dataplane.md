# P09 — Linux Route, Atomic PortRegistry, and Direct TCP Data Plane Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement Linux IPv4 source selection, process-safe socket ownership, direct-v4 listener, TCP half-close proxy, backend snapshot hot update, and truthful data-path evidence.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P07 and P02 integrated; P04 contracts available.

**Wave:** W5B parallel with P08

**Preferred model profile:** Senior Go/Linux network-performance model

---

## Owned files

- Create/own: `internal/traversal/{network.go,fingerprint.go,portregistry.go,socket_linux.go,socket_generic.go}`
- Create/own: `internal/forward/backend.go`, `internal/forward/tcp/**`, `internal/forward/budget.go`
- Create/own Linux tests/fixtures

## Ownership transfer / integration notes

P11 uses PortRegistry interfaces but must not weaken ownership. P12 adds strategy packages. P10 composes activation without rewriting proxy internals.

## Explicit non-goals

No STUN/gateway mapping, UDP, Controller probe, API/UI, Windows support claim.

## Stories

### Story 1: Route and IPv4 capability
- RED: no-v4, no-default-route, private direct source and route changes return stable capability codes.
- GREEN: route/source selection and fingerprint hooks.

### Story 2: Atomic PortRegistry
- RED: port 0, wildcard overlap, duplicate owner, stale release, second process and quick restart.
- GREEN: create/bind/listen in registry critical section and OS single-instance lock.

### Story 3: TCP forwarding and half-close
- RED: long connection, client/server half-close, backend failure and accept backoff.
- GREEN: bidirectional copy with correct CloseWrite behavior.

### Story 4: Backend hot update
- RED: old connection remains old target; new connection uses new snapshot.
- GREEN: atomic backend pointer per accepted session.

### Story 5: Budgets and delete hook
- RED: connection/FD/pessimistic buffer budget exhaustion returns explicit reason; stop closes listener and tracked sessions.
- GREEN: bounded tracking and shutdown interface.

### Story 6: Data-path evidence
- Report `go_tcp_copy_splice_eligible`, never exact runtime splice counters. Lab trace test records evidence separately.

## Required verification

```bash
go test ./internal/traversal ./internal/forward/tcp ./internal/forward -race -count=10
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P09-linux-tcp-direct` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P09.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
