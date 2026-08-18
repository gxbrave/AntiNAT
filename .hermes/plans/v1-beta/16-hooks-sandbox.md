# P16 — Webhook, Isolated JavaScript Runner, Broker, Secrets, and Delivery Queue Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement endpoint events, at-least-once webhook delivery, SSRF-safe broker, constrained request signing, OS-isolated JS runner, DLQ, and lifecycle-aware cleanup.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P14, P15, and P03 integrated; sandbox capability result supplied.

**Wave:** W11

**Preferred model profile:** Application-security/sandbox/SSRF model

---

## Owned files

- Create/own: `internal/hook/**`, `cmd/antinat-hook-runner/**`, `internal/controller/api/hooks.go`, `migrations/0010_hooks.sql`
- Modify P15 router only to register the isolated hook handler after serial ownership transfer
- Create hook fixtures/tests

## Ownership transfer / integration notes

P16 migration numbering follows P15 `0009_api_metrics.sql`; P16 owns
`0010_hooks.sql` and must not reuse an earlier number.

If P03 sandbox gate is not PASS on a platform, expose webhook-only and mark JS unsupported. P17 renders capability; no local shell hook.

## Explicit non-goals

No arbitrary HMAC oracle, shell/local executable, private-network webhook by default, UI styling, installer.

## Stories

### Story 1: Event and durable queue
- RED: stable ID, at-least-once retries, duplicate, backoff, queue full, DLQ and decommission drop semantics.
- GREEN: bounded durable deliveries and observable states.

### Story 2: SSRF-safe transport
- RED: proxy env, mixed public/private A/AAAA, CGNAT/ULA/mapped IPv6, metadata, rebinding, redirects, userinfo/IDNA/CRLF, gzip bomb.
- GREEN: validate-all, IP-pin, preserve SNI/Host, strict headers/size/time.

### Story 3: Secret capability
- RED: runner requests arbitrary bytes, host/path/action or excess calls.
- GREEN: broker signs only normalized final allowlisted request; plaintext secret never enters runner/log.

### Story 4: Runner API
- RED: no network/file/process/reflection/Go bridge; bounded stdin/stdout/schema.
- GREEN: pure encoding/time/request-description runtime.

### Story 5: OS isolation
- Verify Linux UID/env/FD/net+mount namespace/seccomp and native Windows restricted token/AppContainer+Job Object. Fail capability closed.

### Story 6: AliDNS-style fixture
- Generate and broker a correct signed request without provider-specific production adapter; lifecycle event only after verified publication.

## Required verification

```bash
go test ./internal/hook ./internal/controller/api -race -count=10
go test ./internal/hook -run 'SSRF|Sandbox|Secret|Delivery' -count=10
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P16-hooks-sandbox` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P16.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
