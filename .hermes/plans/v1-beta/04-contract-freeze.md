# P04 — Machine-Readable Protocol, State, API, and Installer Contract Freeze Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Convert P02/P03 evidence into normative byte-level and state-level contracts that all later Coding AIs consume without reinterpretation.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P02 and P03 integrated with valid evidence.

**Wave:** W2

**Preferred model profile:** Protocol architect/cryptography model; no implementation bias

---

## Owned files

- Create/own/freeze: `docs/protocol.md`, `docs/state-model.md`, `docs/installer-contract.md`, `docs/test-strategy.md`, `docs/error-codes.md`
- Create/own/freeze: `api/openapi.yaml`, `test/fixtures/compat/**`, `test/fixtures/installer-contract/**`, `internal/protocol/testdata/{control-envelope,enrollment,probe-frame}/**`
- Create validation tests under `test/contracts/**`

## Ownership transfer / integration notes

After integration, these files are frozen at a hash. Later changes require versioned contract revision and orchestrator approval.

## Explicit non-goals

No production protocol parser, server, store, installer, or UI implementation.

## Stories

### Story 1: Normative control/enrollment bytes
- RED: validators reject ambiguous JSON, duplicate fields, bad lengths, wrong domain/direction/epoch/hash.
- GREEN: fixed framing/canonical encoding spec and cross-platform golden vectors.
- VERIFY: valid vectors parse; one-bit mutations fail before payload decode.

### Story 2: Probe wire and operation contract
- Freeze arm/armed, provider-hidden challenge, same-path Agent signature, control receipt, outcome registry, TTL semantics and anti-oracle response.
- Add TCP/UDP golden and replay vectors.

### Story 3: State and lifecycle contract
- Freeze orthogonal activation states, AppliedForwardState, inbox/outbox phases, explicit deletion presence, tombstones, decommission, restore quarantine and key rotation FSM.
- Add state transition fixtures including illegal transitions.

### Story 4: OpenAPI/error/idempotency contract
- Freeze routes, schemas, ETags, idempotency mismatch, pagination, SSE event cursor, force-publish and operation polling.
- Validate OpenAPI and error-code coverage.

### Story 5: Installer and compatibility contract
- Freeze CLI arguments, token FD/file semantics, paths/services, exit codes, N/N-1 fixtures, artifact verification, upgrade/purge states.

### Story 6: Contract manifest
- Produce `test/contracts/manifest.json` with SHA-256 of every frozen artifact and validation command.
- No placeholders in required v1-beta fields.

## Required verification

```bash
go test ./test/contracts/... -count=1 -v
```

`test/contracts` must load and validate every fixture under `internal/protocol/testdata/**`; Go `testdata` directories are fixture data and are not invoked as standalone packages.


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P04-contract-freeze` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P04.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
