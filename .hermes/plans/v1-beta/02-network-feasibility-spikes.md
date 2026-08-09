# P02 — Network Feasibility and Socket Semantics Spikes Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Produce reproducible Go/No-Go evidence for TCP shared-port, atomic PortRegistry, UDP single socket, hidden-challenge probe, layered NAT, and mapping ownership before production architecture is frozen.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P01 integrated.

**Wave:** W1A parallel with P03

**Preferred model profile:** Senior network/OS model with Linux and Winsock expertise

---

## Owned files

- Create/own only: `spike/network/**`, `test/evidence/m0/network/**`, `docs/evidence/m0-network-summary.md`
- May create isolated spike scripts under `spike/network/scripts/**`

## Ownership transfer / integration notes

No production code may be copied from spikes. P04 consumes conclusions. Keep spike source and environment manifests.

## Explicit non-goals

No Controller UI/API, no persistent product schema, no production traversal packages, no unsupported success claims.

## Stories

### Story 1: Linux and Windows TCP shared-port
- RED: prove baseline listener/connected socket conflicts without required pre-bind options.
- GREEN: minimal socket fixtures for unique listener + primary and two remote connected sockets on the same local tuple.
- VERIFY: classify deterministic routing, second-process interference, half-open, close/rebind, stale process. Record native Windows evidence separately.

### Story 2: Atomic PortRegistry/process ownership
- RED: test bind-probe-close-rebind race and second process joining reuse group.
- GREEN: spike socket-owning acquire and OS single-instance lock.
- VERIFY: port 0, wildcard overlap, stale release, old process late exit, concurrent installer start.

### Story 3: UDP single socket and exact-source reply
- RED: payloads resembling STUN/probe must not be consumed without full outstanding match.
- GREEN: one unconnected socket demux fixture and target-response path.
- VERIFY: provider receives authenticated reply from exact published tuple; ICMP/truncation do not kill loop.

### Story 4: Provider-hidden challenge anti-scan
- RED: malicious Agent that sees all control frames cannot answer a challenge it never received at ingress and receives no victim timing oracle.
- GREEN: arm/armed/provider frame/same-path ACK/control receipt fixture.
- VERIFY: TCP/UDP, replay, wrong activation/endpoint/source/TTL, scanner/rate limits.

### Story 5: Layered NAT and ownership
- Build CPE→CGN netns plus at least one real PCP/NAT-PMP/UPnP daemon or router path.
- Assert FIRST_HOP_MAPPED never becomes verified without upstream OPEN_FROM_VANTAGE.
- Assert NAT-PMP port 0 delete is rejected and UPnP mismatched entry is never deleted.

### Story 6: Evidence classification
- Emit one evidence JSON per spike and summary PASS/SUPPORTED_WITH_LIMITS/NO_GO with exact fallback.
- Cleanup every namespace/socket/mapping even on failure.

## Required verification

```bash
go test ./spike/network/... -count=1 -v
sudo -E go test -tags=netns ./spike/network/... -count=1 -v
go run ./scripts/verify-evidence.go ./test/evidence/m0/network
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P02-network-spikes` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P02.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
