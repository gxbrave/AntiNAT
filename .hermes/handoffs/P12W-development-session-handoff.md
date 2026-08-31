# P12W Development-Session Handoff — for the next assistant

**Date:** 2026-08-31. **Author:** prior Claude session (master controller of AntiNAT v1-beta).
**Purpose:** hand over the P12W (Production-Composition Wiring) milestone mid-gate, with the exact state, the review verdicts so far, and the precise un-finished work. Read the TL;DR first.

---

## TL;DR — where things stand RIGHT NOW

- **Milestone P12W is implemented, locally verified, and 2/3 INDEPENDENTLY REVIEWED (approve). It is NOT yet integrated.**
- Candidate branch: `ai/P12W-production-wiring`, in the git worktree `/root/Claude/AntiNAT/p12w-wiring`.
- **Final head: `82ceec5`** (`82ceec57a71efe839838f12e0178be41d9adade5`). Worktree is CLEAN.
- Independent reviews so far:
  - **Spec/ownership: APPROVE** (at `611f25e`) and re-confirmed **APPROVE** at `82ceec5`.
  - **Quality/security: REQUEST_CHANGES** (repair-2) → fixed in repair-3 → **APPROVE** at `82ceec5`.
  - **Network/protocol: LAUNCHED but verdict NOT captured** (it was started at `611f25e`, before repair-3 changed `newStunOnlyActor`/`runDetection`; the session ended before it reported). It must be re-run / re-verified at `82ceec5`.
- **The integration gate is therefore OPEN.** Do NOT start P14, do NOT push to GitHub, until all three reviews approve at the final head AND the full verification matrix is re-recorded at that head, and the candidate is merged onto `integration/v1-beta` and `P12W-integrated.json` is written.
- Documentation lives in `.hermes/handoffs/P12W.json` (machine record with `repair_cycle_1/2/3` blocks), `.hermes/plans/v1-beta/12w-production-wiring.md`, `12w-repair-1.md`, `12w-repair-2.md`, and this file.

---

## What P12W is

P12W closes the P12 production-composition gap: the agent composes the traversal.Manager / Detector / adapters / durable bbolt mapping-journal / same-tuple STUN seams into the real apply/recover/hot-update/lifecycle paths, with strategy-aware acquisition, a durable mapping journal (Story 8 startup replay), capability-aware recover, and mapping-lifecycle → activation wiring. It is the prerequisite for P14 (lifecycle/rotation/recovery), P15 (controller API), etc. The v1-beta contracts (docs/protocol.md, docs/state-model.md, docs/v1-scope-contract.md, docs/support-matrix.md, api/openapi.yaml) are FROZEN.

## Repo / worktree facts (important discipline)

- This is a **git worktree** of the AntiNAT repo. Run all commands from `/root/Claude/AntiNAT/p12w-wiring`. Do NOT `cd` to the original repository root.
- The **stash stack is shared** across worktrees/sessions. **Never use bare `git stash`/`git stash pop`** — you could pop another session's change. Prefer a temporary WIP commit; if you must stash, tag it uniquely, apply by SHA, drop by tag.
- The repo reports `Is a git repository: false` from the worktree's own `.git` file — use `git -C /root/Claude/AntiNAT/p12w-wiring …` or run from the worktree.
- Tests that need the dedicated sandbox identity run as: `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test …`.
- Use `GOWORK=off` for all go commands (no workspace mode).

## Candidate commit lineage (94e08603 = candidate base)

```
82ceec5 hermes: record P12W repair-cycle-3 completion and verification   <== HEAD (handoff record; code identical to 610cd35)
610cd35 agent: P12W repair R3 fix the two dataPlane.cfg data races and harden closing-path release (TDD)   <== last IMPLEMENTATION commit
b0383fd hermes: record P12W repair-2 exact head identity (611f25e)
611f25e hermes: record P12W repair-cycle-2 completion and verification
328f0bb hermes: bound P12W repair-cycle-2 file ownership
971eae2 agent: P12W repair R2 acquisition fencing, same-ID serialization, bounded abandonment, cleanup retry, deletion-window fence (TDD)
c338381 agent: P12W repair R2 strategy semantics — order-walked auto, UDP-first resolution, missing-fingerprint gate, nil-manager errors (TDD)
75868d8 hermes: record P12W repair-cycle-1 completion and verification
37b94c9 hermes: bound P12W repair-cycle-1 file ownership
… (repair-1 fixes, stories S1..S10, plan revisions)
94e08603 candidate base (pre-P12W production-wiring tree)
```

The full P12W implementation is the lineage `94e08603..82ceec5`. The repair-3 delta is `611f25e..82ceec5`. The repair-2 delta is `75868d8..611f25e`.

## The review gate state (exact)

| Review | Verdict | At head | Notes |
|---|---|---|---|
| Spec / ownership | **APPROVE** | `611f25e` + re-confirmed at `82ceec5` | Boundary exact; handoff SHAs/commits/files verified; fixes map to R2f*; no D1–D5 re-litigation; race-oracle probes re-run |
| Quality / security | **APPROVE** | `82ceec5` (after repair-3 closed the two blocking data races) | Blocking findings in repair-2: data race on `d.cfg.StunObserver/StunSource` (newStunOnlyActor) and on `d.cfg.Detector` (runDetection). Both permanently closed + third L-item hardened. Non-blocking residuals listed below |
| Network / protocol | **NOT CAPTURED** | launched at `611f25e` | Session ended before its verdict landed; repair-3 then changed network-facing code. **MUST be re-run at `82ceec5`** |

## Exactly what the next assistant must do (in order)

1. **Re-run the network/protocol review at the final head `82ceec5`.** Scope: the whole P12W candidate (`94e08603..82ceec5`), with emphasis on the repair-3 delta (`611f25e..82ceec5`) touching `newStunOnlyActor` (reads `route.cfg` snapshot), `runDetection` (locked Detector snapshot), and the closing-path branches in `apply`/`finishReopen` (now route through the detached-context `abandonAcquiredActor`). Verify the frozen boundary untouched (`git diff --name-only 94e08603..82ceec5` must not touch `internal/traversal/**`, `internal/forward/udp/**`, `migrations/`, `test/contracts/`, `api/openapi.yaml`, `docs/**`), the UDP bind source is preserved, the gateway/netns lab still maps+releases, and the auto strategy semantics are truthful. Get **APPROVE**.
2. **If any review ever returns REQUEST_CHANGES:** implement a bounded repair cycle (follow the `.hermes/plans/v1-beta/12w-repair-*.md` file-boundary pattern), re-verify the whole matrix, update `.hermes/handoffs/P12W.json` with the new `repair_cycle_N` block, and re-run ALL THREE reviews at the new head. Do not skip any.
3. **Re-record the final verification matrix at the final head** (all exit codes 0):
   ```
   ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
   ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
   GOWORK=off go vet ./...
   GOWORK=off go test ./test/contracts -run TestContractManifest -count=1
   GOWORK=off go test -tags=netns ./test/integration -run 'TestTCPTraversal|TestAgentGatewayTraversal' -count=1
   GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...
   GOOS=linux GOARCH=arm64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...
   GOOS=darwin GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...
   gofmt -l <all changed Go files>   # empty
   git diff --check
   govulncheck   # UNAVAILABLE in this environment — record that honestly, it is not a pass/fail gate
   ```
4. **Integrate ONLY after all three reviews approve at the final head + the matrix above is clean.** Integration = merge/cherry-author the candidate onto `integration/v1-beta` (the prior milestones P01..P13 did this per `.hermes/handoffs/*-integrated.json`), then write **`P12W-integrated.json`** mirroring the earlier integrated-handoffs' shape. Verify the worktree is left clean and the candidate commits are preserved with identity.
5. **After integration:** P14 (lifecycle/rotation/recovery) may begin; the P14 plan is `.hermes/plans/v1-beta/14-lifecycle-rotation-recovery.md`. Do NOT push to GitHub until P12W-integrated.json exists (GitHub sync is the P19 milestone).

## Repair-cycle summary (what the prior session found and fixed)

- **Repair-1** (review of the original candidate at `7308075` → head `37b94c9`): gateway acquisition outside `dataPlane.mu` (HIGH), UDP bind source, stale-profile quarantine at recover, journal-replay wired into production recovery, lifecycle saved-snapshot polling, manual-static keepalive truthfulness, reject literal `--auto-order`, benign metadata-read documentation. All TDD.
- **Repair-2** (fresh review at `75868d8` → head `611f25e`): order-walked auto resolution (Profile.DefaultStrategy is not an authority), UDP auto resolved before TCP profile load, fixed non-direct UDP fails closed, missing-fingerprint gate, nil-manager errors; **generation fencing** (composition/capability generations captured pre-acquisition, checked under the install lock in `apply`/`finishReopen`, bumped on every loss/restore/rebuild); **same-ForwardID serialization** (`beginForwardOperation`); **bounded ownership-preserving abandonment** (`abandonAcquiredActor`) so a canceled caller cannot strand a listener/mapping; **cleanup-completion recovery retry** (`OnActorCleaned` → bounded `recover`); **lifecycle/probe deletion-window fence**; and a fix for a **pre-existing latent double-close** that stranded every gateway actor in `cleanupPending` forever (the wrapped tcp.Forward and the acquisition own the same listener; `exclusiveErrClosed` treats an EXCLUSIVELY redundant `net.ErrClosed` release as clean, never a real mapping/journal failure).
- **Repair-3** (quality/security review → head `82ceec5`): closed the two data races on `dataPlane.cfg` (`newStunOnlyActor` now reads the route's synchronized snapshot instead of live `d.cfg`; `runDetection` snapshots `Detector` under `dataPlane.mu`); hardened the closing-path releases to the detached context; added two **non-vacuously-proven** `-race` oracle probes (`internal/agent/p12w_repair3_races_test.go` — reverting the R3f1 fix makes `-race` report the data race). Full matrix green.

## Known limits / caveats (be honest, don't rediscover)

- **Parallel-race timing flake class:** under full `go test -race ./...` parallel load, occasionally `TestPeriodicReceiptRetrySameSessionAfterChallengeNotEstablished` (internal/agent) and — observed this session — `TestLinuxDirectV4WalkingSkeleton` (test/e2e, "timed out waiting for agent applied forward") can time out. Both pass consistently in isolation under `-race` (e.g. 3/3, ~1.6s each) and the non-race suite passes clean. Do NOT treat a single such timeout as a regression; re-run in isolation and record honestly.
- **govulncheck is NOT installed** in this environment — recorded honestly in the handoffs; it is not a pass/fail gate.
- **D5 residual:** a trailing `OnMapping*` lifecycle event landing after its forward was replaced can still satisfy the mapped guard when the replacement is also live + mapping-capable (no per-acquisition callback token in the traversal library). Documented and accepted; no traversal API change is allowed.
- **Once-only Release semantics (by design):** a manager acquisition whose `Release` genuinely fails stays owned in `cleanupPending` forever — `Acquisition.Release` is `sync.Once` and is NEVER claimed to retry; the durable journal record is the retained evidence the gateway mapping may still be live. This matches repair-2 finding 7's guidance.
- **Non-blocking residuals noted by the quality review (pre-existing, untouched):** documented-benign `JournalID` read under `dp.mu` only (the `""→id` first write under `renewMu` is technically a 2-word write); the cleanup drain's ~100ms `OnCleanupError` retry cadence for a permanently-stranded forward is a log/maintenance firehose; `scheduleCleanupRecoveryRetry` spawns one untracked bounded goroutine per cleanup completion (idempotent, admission-fenced, shutdown-safe).

## Files owned / boundary (the exclusive set; never change anything else for P12W)

- `internal/agent/app.go`, `internal/agent/strategy.go`, `internal/agent/traversal_lifecycle.go`
- P12W tests: `internal/agent/p12w_*.go` (incl. `p12w_repair2_test.go`, `p12w_repair3_races_test.go`)
- Transferred P10/P12W test paths: `internal/agent/app_test.go`, `internal/agent/rollback_fence_test.go` (re-declared owned; unchanged this cycle)
- `internal/agent/applied_recovery_regression_test.go`, `internal/agent/localstate/mapping_journal.go` + tests (Story 1)
- `cmd/antinat-agent/main.go`, `cmd/antinat-agent/autoorder_test.go`
- `test/integration/agent_gateway_test.go`
- `.hermes/plans/v1-beta/12w-*.md`, `.hermes/handoffs/P12W.json`, this file
- **Forbidden for P12W work:** `internal/traversal/**` (incl. `stun/**`), `internal/forward/udp/**`, `migrations/`, `test/contracts/`, `api/openapi.yaml`, `docs/**`, configs, go.mod/go.sum, other worktrees.

## How to read the machine handoff

`.hermes/handoffs/P12W.json` is the authoritative record. Its `repair_cycle_1/2/3` blocks contain per-finding → fix, per-commit SHA/subject, exact verification commands with exit codes, and deviations. `head_sha` / `repair_cycle_2.head` / `repair_cycle_3.head` follow the self-referential convention that the hermes-record commit itself is the head (the implementation head is the last `agent:` commit; each hermes-record commit changes only the handoff JSON). This is a documented, benign convention, not a discrepancy.