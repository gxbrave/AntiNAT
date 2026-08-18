# P12 — Gateway Mapping Adapters, Layered Strategy, and Node Detection Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Implement PCP, NAT-PMP, UPnP IGD, layered gateway+STUN strategies, mapping journal, node detection/profile/fingerprint, manual-static verification, and TCP traversal integration.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P10 and P11 integrated.

**Wave:** W7

**Preferred model profile:** NAT protocol architect with PCP/NAT-PMP/UPnP expertise

---

## Owned files

- Create/own: `internal/traversal/{strategy.go,detection.go,profile.go,mapping_journal.go,manager.go}`
- Create/own: `internal/traversal/{pcp,natpmp,upnp,direct,manual}/**`
- Create/own: `migrations/0007_traversal.sql`, `test/integration/traversal_tcp_test.go`, `test/netns/**`

## Ownership transfer / integration notes

- P10 owns `migrations/0004_probe.sql`, `migrations/0005_probe_hardening.sql`, and
  `migrations/0006_r13_hardening.sql`. Traversal schema work starts at
  `0007_traversal.sql`; do not rename, edit, or reuse prior migration numbers.

P13 adds UDP protocol use through interfaces. P14 consumes mapping cleanup/recovery. Applied migrations are immutable.

## Explicit non-goals

No UDP business proxy, full API/UI, installer, or claims beyond adapter evidence.

## Stories

### Story 1: Strategy/layer contract
- RED: non-global first hop, unsupported multiple explicit layers, fixed strategy fallback, final port constraint and replacement capability.
- GREEN: pipeline and structured evidence.

### Story 2: PCP
- RED: nonce, result/lifetime, epoch rollback, retry, PREFER_FAILURE and lifetime=0 delete.
- GREEN: MAP subset with strong ownership journal.

### Story 3: NAT-PMP
- RED: public address/map opcodes, assigned port, epoch/reboot; internal port 0 delete always rejected.
- GREEN: weak lease ownership and safe expiry-first cleanup.

### Story 4: UPnP IGD
- RED: interface-bound SSDP, multiple IGD, LOCATION/control URL scope, size/redirect/USN/restart, IGDv1/v2 ports and mismatched delete.
- GREEN: best-effort query-then-delete with permanent-only policy.

### Story 5: Composition/manual
- Verify gateway non-global + same-source STUN + independent probe; manual-static only after operator endpoint input.

### Story 6: Detection/profile
- Sequential default, bounded parallel temp tuples, cleanup, all-failed save, TCP/UDP separate defaults, fingerprint and age stale.

### Story 7: TCP traversal lab
- Fake faults + independent daemon + available real router; classify each adapter beta/experimental honestly.

## Required verification

```bash
go test ./internal/traversal/... -race -count=10
sudo -E go test -tags=netns ./test/integration -run TestTCPTraversal -count=1 -v
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P12-gateway-traversal` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P12.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
