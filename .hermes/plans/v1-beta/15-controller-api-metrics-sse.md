# P15 — Complete Controller API, SSE, Rate Limiting, and Metrics Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement the full frozen admin API, middleware, durable SSE, traffic ingest/rollups, Forward aggregate limits, capability-aware validation, and operation status exposure.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P14 and P06 integrated.

**Wave:** W10

**Preferred model profile:** Go web/API/database model with security and concurrency expertise

---

## Owned files

- Create/own: `internal/controller/api/**`, `internal/controller/web/{router.go,middleware.go,sse.go}`
- Create/own: `internal/metrics/**`, `internal/forward/limiter.go`, `internal/controller/store/traffic.go`, `migrations/0009_api_metrics.sql`
- Modify transferred minimal P10 API/router/app files

## Ownership transfer / integration notes

Migration numbering follows P10 `0006_r13_hardening.sql`, P12
`0007_traversal.sql`, and P14 `0008_lifecycle.sql`; P15 owns
`0009_api_metrics.sql` and must not reuse an earlier number.

P16 adds hook-specific handler files serially. P17 consumes APIs and owns UI. Do not modify frozen OpenAPI without approved contract revision.

## Explicit non-goals

No HTML/CSS/JS UI, hook runner, installer, traversal adapters.

## Stories

### Story 1: Security middleware
- RED: CSRF/Origin, session, body limit, request ID, login rate, trusted proxy and secret-log cases.
- GREEN: middleware with consistent errors and cookie flags.

### Story 2: Nodes/forwards/operations
- RED: permissions, ETag 428/412, idempotency mismatch, capability/port conflicts, offline delete, force publish and force delete status.
- GREEN: handlers matching frozen OpenAPI.

### Story 3: Navigation/settings/deployment profile
- RED: ordering conflicts, private-site behavior, explicit controller endpoint and secret visibility.
- GREEN: CRUD services/handlers; no final UI.

### Story 4: Durable SSE
- RED: reconnect Last-Event-ID, restart, slow client/backpressure and secret redaction.
- GREEN: event store cursor and bounded subscribers.

### Story 5: Limits and metrics
- RED: fake-clock rate/burst/direction, NEW_SESSIONS_ONLY, legacy count, delta duplicate/out-of-order and disabled-history behavior.
- GREEN: aggregate limiter and opt-in detailed deltas/rollups.

### Story 6: OpenAPI conformance
- Run generated/request fixtures against handlers; every documented error code has a test.

## Required verification

```bash
go test ./internal/controller/api ./internal/controller/web ./internal/controller/store ./internal/metrics ./internal/forward -race -count=10
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P15-controller-api-metrics` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P15.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
