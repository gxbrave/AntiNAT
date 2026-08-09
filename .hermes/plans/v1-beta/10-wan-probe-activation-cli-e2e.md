# P10 — WAN Probe, Activation State Machine, Minimal Admin CLI, and M1 E2E Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Compose enrollment/control and direct TCP into the first runnable vertical slice with hidden-challenge WAN verification, orthogonal activation state, minimal authenticated API/CLI, app composition, and online delete.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P08, P09, and P06 integrated.

**Wave:** W6A parallel with P11 after P09

**Preferred model profile:** Senior end-to-end Go architect with network security expertise

---

## Owned files

- Create/own: `internal/controller/probe/**`, `cmd/antinat-probe/**`, `internal/agent/reconcile/{activation.go,probe.go,state_machine.go}`
- Create/own: `internal/controller/api/{auth.go,nodes_min.go,forwards_min.go,health.go}`, `internal/controller/web/router_min.go`
- Create/own: `cmd/antinatctl/**`, `internal/controller/app.go`, `internal/agent/app.go`, `test/e2e/walking_skeleton_test.go`, `test/e2e/harness/**`
- Modify declared P07/P08/P09 extension points only

## Ownership transfer / integration notes

P15 later replaces/extends minimal router/API serially. P13 extends probe for UDP. P14 extends lifecycle. P19 owns final E2E aggregation.

## Explicit non-goals

No STUN/gateway/UDP/full UI/hooks/installer/force-node-delete.

## Stories

### Story 1: Probe arm and provider request
- RED: provider cannot run before durable `probe_armed`; challenge must never appear in control capture.
- GREEN: Controller operation and provider-signed request.

### Story 2: TCP same-path ACK and control receipt
- RED: connect-only, Agent-only receipt, wrong source/activation/endpoint/TTL/replay fail.
- GREEN: exact join of provider result + Agent receipt; Agent sees no victim timing oracle.

### Story 3: Orthogonal activation/publication
- RED: mapping/listener/target/WAN/publication states vary independently; old event cannot overwrite current CAS.
- GREEN: activation state machine and immediate stale/unpublish on evidence loss.

### Story 4: Minimal authenticated API and CLI
- RED: unauthenticated access, missing If-Match, idempotency mismatch and secret output fail.
- GREEN: admin init/login, node/Forward/status/delete CLI path.

### Story 5: App composition
- RED: startup failure rolls back readiness; signal shutdown closes resources in order.
- GREEN: Controller/Agent/probe mains, health/readiness and graceful shutdown.

### Story 6: M1 walking skeleton
- From empty state: init admin→create node→enroll→direct-v4 Forward→WAN probe→external echo→target hot update→Agent restart UNVERIFIED→reprobe→online delete→restart no resurrection.
- Persist logs/state/socket dump on failure.

## Required verification

```bash
go test ./internal/controller/probe ./internal/agent/reconcile ./internal/controller/api ./cmd/antinatctl -race -count=1
go test ./test/e2e -run TestLinuxDirectV4WalkingSkeleton -count=1 -v
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P10-probe-activation-e2e` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P10.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
