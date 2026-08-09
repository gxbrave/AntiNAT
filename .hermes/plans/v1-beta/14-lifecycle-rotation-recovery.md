# P14 — Deletion, Decommission, Key Rotation, Backup, and Recovery Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Complete crash-safe Forward deletion, normal/force node decommission, cleanup-only identity, key rotations, uninstall notice, backup barriers, and anti-rollback recovery quarantine.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P08, P12, and P13 integrated.

**Wave:** W9

**Preferred model profile:** Distributed-systems/security/recovery model

---

## Owned files

- Create/own: `internal/agent/reconcile/{delete.go,decommission.go,recovery.go}`
- Modify with transferred ownership: P07 localstate lifecycle files, P08 keyring/control rotation files
- Create/own: `internal/controller/lifecycle/**`, `internal/controller/recovery/**`, `migrations/0005_lifecycle.sql`, `docs/recovery.md`
- Create lifecycle crash/integration tests

## Ownership transfer / integration notes

P15 exposes operations through API. P18 invokes uninstall/recovery interfaces. Existing migrations/contracts immutable without revision.

## Explicit non-goals

No UI, hook runner, installer implementation, or silent remote-stop guarantee for offline Agent.

## Stories

### Story 1: Forward delete FSM
- RED: kill at operation/outbox/inbox/tombstone/stop/result/ACK/receipt; old snapshot never resurrects.
- GREEN: explicit ABSENT operation, stop, best-effort mapping release, durable receipt/GC.

### Story 2: Normal node decommission
- RED: marker/apply race, partial stop, gateway failure, ACK loss and restart.
- GREEN: terminal latch, stop-all, secret/LKG/job cleanup, minimal ACK identity.

### Story 3: Force delete/cleanup-only
- RED: old key cannot receive desired or secrets; never-reconnect remains unconfirmed.
- GREEN: cleanup tombstone with key versions and restricted session.

### Story 4: Key rotation
- RED: every PREPARED→RETIRED crash point, offline Agent, downgrade and force-retire.
- GREEN: Controller/Agent/master/hook/probe key operation journals and overlap.

### Story 5: Backup/restore
- RED: backup after delete then restore old state, key mismatch, bit flip, concurrent rotation/migration.
- GREEN: barrier, manifest, staging restore, RESTORE_RECONCILIATION and Agent RECOVERY_QUARANTINE.

### Story 6: Agent uninstall notice
- Online bounded receipt vs offline unknown; local terminal marker always prevents LKG recovery.

## Required verification

```bash
go test ./internal/agent/localstate ./internal/agent/reconcile ./internal/controller/lifecycle ./internal/controller/recovery -race -count=20
go test ./test/integration -run 'Delete|Decommission|Recovery|Rotation' -count=1 -v
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P14-lifecycle-recovery` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P14.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
