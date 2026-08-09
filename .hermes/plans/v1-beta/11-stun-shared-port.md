# P11 — STUN RFC8489 and Shared-Port Socket Layer Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement bounded STUN TCP/UDP codecs and clients, transport-specific endpoint health, Linux/Windows shared-port socket behavior, and honest concurrent mapping evidence.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P09 and P04 integrated; P02 evidence supplied.

**Wave:** W6B parallel with P10 after P09

**Preferred model profile:** STUN/RFC and cross-platform socket model

---

## Owned files

- Create/own: `internal/traversal/stun/**`
- Create/own: `internal/traversal/socket_windows.go` and STUN-specific platform socket adapters
- Read-only use of P09 PortRegistry interfaces and frozen fixtures

## Ownership transfer / integration notes

P12 consumes STUN interfaces. P13 consumes UDP transaction demux hooks. Do not change PortRegistry ownership rules without contract revision.

## Explicit non-goals

No strategy scheduler, gateway adapters, publication, UI, or full Windows support claim without native evidence.

## Stories

### Story 1: STUN message codec
- RED: malformed lengths, unknown required attributes, XOR address, ERROR-CODE/300, fingerprint/integrity boundary.
- GREEN: bounded codec or vetted dependency adapter controlled by AntiNAT.

### Story 2: UDP client
- RED: wrong source/class/transaction, retransmit/backoff/deadline and alternate-server policy.
- GREEN: transaction-safe UDP exchange using caller-owned socket.

### Story 3: TCP framing/client
- RED: partial header/body, oversize, disconnect, timeout; no STUN-layer retransmit over TCP.
- GREEN: persistent transport with clean mapping invalidation on disconnect.

### Story 4: Shared-port sockets
- RED: listener plus connected sockets, duplicate listener, wildcard overlap, stale owner close on Linux and native Windows.
- GREEN: platform adapters using P09 registry ownership.

### Story 5: Mapping evidence
- Concurrent two-destination observation only when first connection stays established and platform gate passes; otherwise PORT_REUSE_OBSERVED/MAPPED_UNVERIFIED.

### Story 6: Endpoint health/fuzz
- DNS/IP/cooldown/RTT/success-rate separated per transport; fuzz never panics.

## Required verification

```bash
go test ./internal/traversal/stun -race -count=10
go test ./internal/traversal/stun -fuzz=Fuzz -fuzztime=30s
GOOS=windows GOARCH=amd64 go test -c ./internal/traversal/stun
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P11-stun-shared-port` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P11.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
