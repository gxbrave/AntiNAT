# P08 — Enrollment, Bidirectional Identity, and Durable WebSocket Control Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement proof-of-possession enrollment, Controller pinning, signed control sessions, bidirectional epoch fencing, reconnect, and durable semantic delivery.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P06 and P07 integrated; P04/P05 contracts frozen/implemented.

**Wave:** W5A parallel with P09

**Preferred model profile:** Cryptography/protocol/concurrency model

---

## Owned files

- Create/own: `internal/security/{nodekey,challenge,keyring}.go`
- Create/own: `internal/controller/agenthub/**`, `internal/agent/control/**`
- Create/own: `migrations/0003_enrollment.sql`
- Modify only declared P07 control persistence interfaces

## Ownership transfer / integration notes

P14 later extends key rotation/cleanup-only flows after serial ownership transfer. P10 consumes the channel via interfaces.

## Explicit non-goals

No traversal sockets, data proxy, UI, full admin API, installer.

## Stories

### Story 1: Enrollment challenge/request/result
- RED: cross-node/controller/nonce replay, wrong possession key, expired token and response-loss cases.
- GREEN: signed transcript, atomic consume/bind/result, same-node/same-key idempotent recovery.

### Story 2: Secret-safe bootstrap
- RED: capture logs/errors/store and assert token/private key absent.
- GREEN: token hash-only store integration and key file/DPAPI abstraction.

### Story 3: Signed session handshake
- RED: wrong pinned Controller, wrong Agent key, direction, domain, epoch, session and sequence fail.
- GREEN: mutual challenge and signed frames over bounded WebSocket.

### Story 4: Bidirectional epoch fencing
- RED: two sessions; old socket sends valid signed command/ACK after new epoch.
- GREEN: Controller CAS plus Agent persisted max epoch before socket activation.

### Story 5: Reconnect and semantic resend
- RED: disconnect at write/inbox/result/ACK/receipt phases.
- GREEN: new-session re-envelope of same operation without duplicate side effect.

### Story 6: Transport boundaries
- Validate A-only, AAAA-only, dual fallback; plaintext public enrollment refused by default; message/body/queue limits enforced.

## Required verification

```bash
go test ./internal/security ./internal/controller/agenthub ./internal/agent/control -race -count=10
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P08-enrollment-control` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P08.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
