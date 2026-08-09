# P05 — Protocol Codec, Domain Model, and Strict Configuration Core Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement frozen control/enrollment/probe framing, versioned domain types, strict validation, endpoint classification, and configuration parsing.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P04 integrated; contract manifest hash supplied.

**Wave:** W3

**Preferred model profile:** Go protocol/security implementation model

---

## Owned files

- Create/own: `internal/protocol/**` except frozen `testdata/**`
- Create/own: `internal/config/**`, `internal/security/framecrypto/**`
- Test owned packages

## Ownership transfer / integration notes

P10 may add a probe orchestration adapter file only through declared interface. Frozen fixtures remain read-only.

## Explicit non-goals

No sockets, WebSocket session, DB, Agent state, business API, traversal implementation.

## Stories

### Story 1: Fixed frame parser
- RED: each malformed length/domain/hash/signature vector fails before payload decode.
- GREEN: bounded parser/encoder over exact protected bytes.
- VERIFY: frozen vectors and bit-flip table.

### Story 2: Strict payload decoding
- RED: duplicate keys, unknown fields, deep nesting, oversized values and numeric overflow fail.
- GREEN: strict bounded decoder and stable error codes.

### Story 3: Domain types and validation
- RED: invalid state enum, port constraints, v6 Forward, private published candidate, impossible layer relation fail.
- GREEN: types for DesiredState, ForwardSpec/Activation, AppliedForwardState, operations, probe and capability results.

### Story 4: Endpoint/network classes
- RED: table for RFC1918, CGNAT, loopback, link-local, benchmark/documentation/multicast/reserved and IPv4-mapped IPv6.
- GREEN: explicit classification, not IsGlobalUnicast alone.

### Story 5: Config parsing
- RED: unknown keys, insecure public enrollment default, malformed URLs and invalid bounds fail.
- GREEN: Controller/Agent configs with safe defaults and no secret logging.

### Story 6: Fuzz/regression
- Fuzz frame, JSON payload, endpoint and config; no panic or unbounded allocation.

## Required verification

```bash
go test ./internal/protocol ./internal/config ./internal/security/framecrypto -race -count=1
go test ./internal/protocol -run Golden -count=1
go test ./internal/protocol -fuzz=Fuzz -fuzztime=30s
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P05-protocol-core` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P05.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
