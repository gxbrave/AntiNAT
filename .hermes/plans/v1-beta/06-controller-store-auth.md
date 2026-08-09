# P06 — Controller SQLite Store and Authentication Services Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement transactional Controller persistence, migrations, backups, admin password/session services, idempotency storage, and low-disk priorities.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P05 integrated.

**Wave:** W4A parallel with P07

**Preferred model profile:** Go database/reliability model with SQLite expertise

---

## Owned files

- Create/own: `migrations/0001_core.sql`, `migrations/0002_control.sql`
- Create/own: `internal/controller/store/**`, `internal/controller/auth/**`
- Create/own tests and store fixtures

## Ownership transfer / integration notes

P15 later adds new migrations and API handlers; it must not rewrite applied P06 migrations. P14 may consume operation transactions through interfaces.

## Explicit non-goals

No HTTP router, UI, WebSocket, Agent code, traversal, hooks.

## Stories

### Story 1: Migration and constraints
- RED: migration idempotency, FK, required stable `forwards` parent, deletion rows surviving cascade, revision/CAS conflicts.
- GREEN: core schema and migration runner.

### Story 2: Transactional desired/delete/outbox
- RED: fault injection between desired change, operation and outbox must roll back all.
- GREEN: transaction methods for nodes/forwards/delete/control outbox.

### Story 3: Idempotency and durable admin events
- RED: same key/same hash replays result; same key/different hash conflicts; SSE cursor survives restart.
- GREEN: idempotency and admin event stores.

### Story 4: Password/session services
- RED: Argon2id verify/migration, session hash/expiry/revoke, random admin secret, no plaintext persistence/logging.
- GREEN: service layer without HTTP handlers.

### Story 5: WAL/backup/low disk
- RED: concurrent WAL writes plus backup restore, busy timeout, disk thresholds, stop/delete priority.
- GREEN: configured SQLite and consistent backup API/VACUUM INTO.

### Story 6: Corruption and migration failure
- Ensure old DB remains intact and startup fails closed with actionable error.

## Required verification

```bash
go test ./internal/controller/store ./internal/controller/auth -race -count=1
go test ./internal/controller/store -run 'Backup|Migration|Delete|Idempotency' -count=10
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P06-controller-store-auth` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P06.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
