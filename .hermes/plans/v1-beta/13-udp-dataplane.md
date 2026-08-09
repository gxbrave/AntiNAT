# P13 — UDP Single-Socket Data Plane, Sessions, and WAN Probe Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement one UDP ingress socket for STUN/keepalive/probe/business traffic, bounded per-client sessions, exact-source replies, UDP hidden-challenge verification, and target hot update semantics.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P10, P11, and P12 integrated.

**Wave:** W8

**Preferred model profile:** High-concurrency UDP/Go network model

---

## Owned files

- Create/own: `internal/forward/udp/**`
- Create/own: UDP extension files in `internal/controller/probe/udp.go`, `internal/agent/reconcile/probe_udp.go`
- Create/own: `test/integration/udp_test.go` and UDP netns fixtures

## Ownership transfer / integration notes

P14 consumes stop/session cleanup interfaces. Do not create a second ingress or connected keepalive socket.

## Explicit non-goals

No new traversal adapter, UI, installer, or zero-copy claim.

## Stories

### Story 1: Strict demux
- RED: ordinary payload resembling STUN/probe/keepalive must reach business path unless full outstanding transaction/source/provider/activation matches.
- GREEN: deterministic one-socket classifier.

### Story 2: Session table
- RED: per-client isolation, idle expiry, source churn, same client during target revision, global/per-IP bounds.
- GREEN: sharded bounded sessions and connected target sockets.

### Story 3: Exact-source target replies
- RED: target response sent from ephemeral wrong source fails.
- GREEN: route replies through ingress socket to published client tuple.

### Story 4: Truncation/MTU/ICMP
- RED: truncated datagram never forwarded; correlated ICMP only affects matching session; Windows connreset does not kill ingress.
- GREEN: platform-aware read/error handling and bounded 65,507-byte pool.

### Story 5: UDP hidden-challenge probe
- RED: sendto-only, Agent-only receipt, wrong source/TTL/replay fail; response cannot amplify.
- GREEN: exact tuple ACK plus control receipt join.

### Story 6: Exhaustion and E2E
- Test session, FD/handle, buffer, ephemeral port and flood limits; UDP external echo and target hot update pass.

## Required verification

```bash
go test ./internal/forward/udp ./internal/controller/probe ./internal/agent/reconcile -race -count=10
sudo -E go test -tags=netns ./test/integration -run TestUDP -count=1 -v
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P13-udp-dataplane` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P13.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
