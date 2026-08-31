# P12W Repair Cycle 1 — Bounded fix of independent quality/security review findings

**Owner (after review):** existing P12W candidate branch `ai/P12W-production-wiring` in /root/Claude/AntiNAT/p12w-wiring.

**Scope:** Fix ONLY the findings listed below from the independent quality/security review of P12W head `7308075` (now `0c7bad3` after the spec-resolution plan/handoff commits). Do not implement new features, broaden scope, re-litigate accepted decisions (D1–D5), or modify the accepted `traversal`/`stun`/`internal/forward/udp` libraries.

## Repair-cycle file boundary

The repair cycle may modify only the following production/test paths, in addition to this repair plan and the P12W handoff metadata:

- `internal/agent/app.go`, `internal/agent/strategy.go`, `internal/agent/p12w_composition_test.go`, `internal/agent/p12w_lifecycle_test.go`, and `internal/agent/p12w_recovery_test.go` — bounded changes for findings 1–4, 6–9.
- `internal/agent/applied_recovery_regression_test.go` — two-line signature-only adaptation required because `dataPlane.recover` now returns a recovery report; no behavior change.
- `internal/agent/p12w_quarantine_test.go` — new mixed stale-profile recovery test for finding 3.
- `cmd/antinat-agent/main.go` and `cmd/antinat-agent/autoorder_test.go` — reject literal `auto` and test that parser boundary for finding 8.
- No other source/test paths are in scope. The accepted `internal/traversal/**`, `internal/traversal/stun/**`, and `internal/forward/udp/**` libraries, frozen contracts, migrations, and manifests remain out of scope.

## Findings to fix (severity-ranked)

1. **HIGH — `apply` holds the global `dataPlane.mu` across the gateway manager acquisition (external network RPC).**
   `internal/agent/app.go` — the new-install path calls `d.newForwardActor(...)` while `d.mu` is held; the gateway path runs `Manager.Acquire` with mapper Discover/Map + same-tuple STUN observation (seconds of network I/O), serializing every concurrent forward op (hot-update, delete `stop`, `monitorLiveness` teardown, `closeAll` admission-wait). This is a NEW widening vs the pre-existing fast OS-bind hold. `recover` already performs acquisition outside `d.mu` and only re-locks via `finishReopen` — **mirror that two-phase pattern**: resolve the route + acquire the lease/actor OUTSIDE the lock, then re-lock for the (existing) delete-fence re-checks and the `d.forwards` install + supervisor start. Preserve every existing fence/race/rollback guarantee exactly (probeAdmissionMu → dp.mu ordering, cleanup single-flight, release-on-error-once). Also apply the same outside-the-lock discipline to the hot-update path's `resolveForwardRoute`/profile-file/fingerprint reads (LOW finding 5) — resolve the route before taking `d.mu`, compare under the lock.

2. **MEDIUM — UDP forward listener bind silently changed from the selected global source to wildcard `0.0.0.0`.**
   `internal/agent/app.go` — the UDP branch (`newUDPActor`) must resolve `traversal.Assess(cfg.RouteTable)` and pass the selected global source address to `AcquireUDP` exactly as the pre-P12W path did, restoring the accepted P13 bind-host behavior ("UDP path untouched"). Add a test pinning the UDP bind host to the selected source (extend an existing dataPlane composition test).

3. **MEDIUM — a stale/absent detection profile can fail the entire agent startup for applied `auto` TCP forwards.**
   `internal/agent/app.go` `recover`/`reopen` — when an applied `auto` forward's cached profile is stale/absent (or its fingerprint changed), `reopen` today returns an error that aborts the whole recovery (`App.Start` then fails and the detection job — which could refresh the profile — only runs after recovery). Fix: **quarantine the un-resolvable `auto` forwards** (keep the applied LKG durably, mark the forward non-applied/retry-intent, surface the error per forward) instead of failing the whole `recover`; let the existing detection job re-populate the profile and then recover the quarantined forwards. Direct-v4 / manual / gateway-with-resolved-profile forwards on the same node must still recover. Add a recover test covering the mixed stale-profile + healthy-forwards case.

4. **MEDIUM — `replayJournalBoundaries` is dead code (only called from its test).**
   Wire it into the production recovery/startup path (`recover` or readiness) and surface the resulting `Superseded`/`Orphaned` records through the existing status/diagnostic surface (or at minimum the agent log) so the Story 8 "surfaced by a diagnostic" claim is true in production. Keep the not-silently-deleted semantics (P14 evacuates with State decode).

5. **(folded into 1)** LOW — hot-update route/profile/fingerprint resolution under `d.mu`.

6. **LOW — new test flake in `TestMappingLifecycleDegradedThenRecovered`** (`internal/agent/p12w_lifecycle_test.go`). The test polls only the in-memory activation to `HEALTHY` then reads the persisted snapshot once; the axis is made visible before `SaveActivationSnapshot` completes, so under load the store read can still show `DEGRADED`. Fix: poll the SAVED snapshot for `HEALTHY` (a waitForSaved helper) before the final assertion.

7. **LOW — manual-static forwards claim `keepalive_state HEALTHY` with no renewal loop.** For manual acquisitions (no renewal), set a truthful axis (`NOT_REQUIRED`, or gate on the acquisition having a running renewal) rather than claiming HEALTHY.

8. **INFO — `--auto-order` accepts the literal `auto` strategy**, which silently produces a no-default detection profile. Reject `auto` in `cmd/antinat-agent/main.go` `parseStrategyOrder` (it is not a probeable concrete strategy; only the order entries post-resolver are). Keep rejecting unknown names and `manual-static-v4`.

9. **INFO — unsynchronized reads of `acq.JournalID`/`acq.Verdict`** in `acquisitionMetaFromAcquisition` and `replayJournalBoundaries` are outside `renewMu`. Add a short comment documenting the benign reasoning (Verdict immutable after acquire; JournalID monotone `"" → stable`), or use a locked accessor if available — no behavior change required.

## Not to fix (accept as documented)

- fsync-per-renewal under `renewMu` (bounded single-tx, per the JournalStore contract) — already in known_limits.
- S10 commit message wording (`TDD`) — Story 10 is compile-only per plan; acceptable.
- D5 residual stale-window guard — accepted decision, already disclosed.

## Method

Strict TDD where a behavior test can express the fix (findings 2, 3, 6, 7, 8): write/adjust the failing test first, confirm RED (or demonstrate the current wrong behavior), then GREEN. For structural fixes (findings 1/4/5/9), demonstrate the current gap where feasible, implement, and re-run the full P12W + affected-package verification. Commit each fix coherently (e.g. `agent: P12W repair R1 <slug> (TDD)`), so the review delta is clean.

## Verification after repair (must all pass with recorded exit codes)

```bash
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./internal/agent -run 'P12W|Strategy|Composition|Recovery|Lifecycle|HotUpdate|Capability' -race -count=10
GOWORK=off go vet ./...
GOWORK=off go test ./test/contracts -run TestContractManifest -count=1
GOWORK=off go test -tags=netns ./test/integration -run 'TestTCPTraversal|TestAgentGatewayTraversal' -count=1
GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...
GOOS=linux GOARCH=arm64 GOWORK=off go build ./cmd/... ./internal/traversal/... ./internal/forward/...
gofmt -l <all changed .go files>  # empty
git diff --check
```

Note: a pre-existing timing-sensitive receipt test can flake under full parallel race load; if it fails, re-run it in isolation and report accordingly — do not modify it.

## Output

Update `.hermes/handoffs/P12W.json` with a `repair_cycle_1` block listing each finding → fix → verification exit codes, and any deviation (or "none"). Report back: the commit list, files changed per finding, all verification command exit codes, and confirmation that no out-of-scope change was made.