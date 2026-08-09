# P19 — v1.0-beta Integration, Evidence Verification, and Release Candidate Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Integrate and validate the exact artifact set from P01-P18, run real network/platform/security/soak gates, publish truthful support status, and produce an approved v1.0-beta candidate without directly fixing production code.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P01 through P18 integrated and independently approved.

**Wave:** W14

**Preferred model profile:** Fresh release/integration orchestrator with security and network evidence expertise

---

## Owned files

- Create/own: `test/e2e/**` final suites, `test/release/**`, `scripts/run-beta-gates.sh`, `scripts/verify-release-evidence.go`, `.github/workflows/release.yml`
- Create/own: `docs/beta-release-checklist.md`, `docs/nat-support.md`, `docs/release-policy.md`, `CHANGELOG.md`
- May update README/support matrix only to reflect evidence; no broader claims

## Ownership transfer / integration notes

P19 must not fix production packages. Route failures to owning child/fix AI, re-review, reintegrate, rebuild once, and rerun affected gates.

## Explicit non-goals

No feature implementation, no suppressing failures, no evidence fabrication, no test-after-rebuild digest mismatch, no GA SLO claim.

## Stories

### Story 1: Handoff and contract audit
- Validate P01-P18 handoffs, integrated SHAs, contract hashes, file ownership and capability statuses.
- Fail on missing evidence or undeclared edits.

### Story 2: Build once and record digest
- Produce Linux/Windows/OCI candidates, SBOM, checksums and signatures.
- All remaining tests target these exact digests.

### Story 3: Full functional E2E
- Empty install→admin→node→enroll→TCP/UDP direct/manual/STUN/gateway as supported→UI→hot update→restart→delete/decommission→uninstall.
- Verify Controller never carries user payload.

### Story 4: Real WAN/NAT and platform matrix
- Independent WAN client and provider; restart Agent/router/WAN; native Windows/OpenRC/arm64 according to claimed status.
- Experimental/unsupported adapters stay hidden/labeled.

### Story 5: Security/fault gate
- Control replay/epoch, probe anti-oracle, SSRF/sandbox, disk full/DB busy/corruption, restore quarantine, manifest path attacks, token/secret scans.

### Story 6: Performance/resource beta gate
- Short paired direct/proxy benchmark, 1k/10k idle where hardware permits, SYN/slowloris/UDP churn/buffer exhaustion and at least 24h primary Linux soak.
- Report metrics; do not claim formal GA 2 Gbps/<1ms unless formal evidence exists.

### Story 7: Install/upgrade/purge gate
- Fresh artifact install, N/N-1 upgrade, forced rollback, complete residue scan for each promoted platform.

### Story 8: Promotion review
- Independent release reviewer checks exact digest, support matrix, known limits, changelog, rollback and signatures.
- Tag `v1.0.0-beta.1` only after approval; promotion does not rebuild artifacts.

## Required verification

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
./scripts/run-beta-gates.sh --artifacts ./dist --evidence ./artifacts/evidence
go run ./scripts/verify-release-evidence.go ./artifacts/evidence
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P19-beta-release` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P19.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
