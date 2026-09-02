# Current Development State

**Snapshot date:** 2026-09-02
**Authoritative repository:** `/root/Claude/AntiNAT/p12-integration`
**Authoritative baseline:** `329fdf5039e4e55350d923462f78c2d4ee2e3588` on `integration/v1-beta` (P16 integrated; cherry-picked onto the P15 integrated tip `fa1fb739810ab8c81d0b2dbb246d5ce9a6e2c5edb`; P15, P14, P12W, P13 and prior are in ancestry)

This document is the current consolidation view. August handoff and project-plan documents under `/root/Claude/AntiNAT/AntiNAT` remain preserved historical snapshots; do not rewrite them or treat their earlier “bootstrap-only,” “P10 blocked,” or “P12–P19 not started” statements as current status.

## Executive state

- P01–P15 and P12W are integrated into the authoritative baseline. P04's implementation is in the ancestry, but its integrated record had to be reconstructed from preserved provenance; see `.hermes/handoffs/P04-integrated.json` and its explicit evidence qualifications.
- P13 is **integrated** (2026-08-31) at integrated tip `9298a6c2f97c07c443ceda96b8405bc8b01f9188`; all P13 files byte-identical to reviewed candidate tip `8f56e973722ff378881806c11e658ee8c9d96136`. See `.hermes/handoffs/P13-integrated.json`.
- **P12W is integrated** (2026-08-31) at integrated tip `708931ec8667e460b73e05f741cb18a3c4b6dbe6`; it closes the P12 production-composition gap. See `.hermes/handoffs/P12W-integrated.json`.
- **P14 is integrated** (2026-09-01) at integrated tip `52e6922f50e3cb98ee8c2a611ee757753a73aa69`, fast-forwarded from `ecdd115284c728d8b89960d8619a6d0cf69e047c` with the approved repair-7 candidate. It delivers Forward deletion, normal/force decommission and cleanup-only gating, key rotation, backup/restore anti-rollback, recovery quarantine, and uninstall notice lifecycle. Independent final spec/ownership and quality/security reviews both APPROVE. See `.hermes/handoffs/P14-integrated.json` and `.hermes/handoffs/P14.json`.
- **P15 is integrated** (2026-09-02) at integrated tip `0f310193b16509d8578d011914f79af3f004c8b5`, fast-forwarded from `d335b09f127de03254ca5119244006c41444ff0a` with the approved repair-cycle-2 candidate. It delivers the complete frozen Controller API (nodes/forwards paging/sort/filter, ETag CAS with 412 semantics, force-publish and force-delete lifecycle, durable navigation/settings idempotency), durable bounded SSE on `/api/v1/events` (Last-Event-ID replay, secret redaction, bounded subscribers), metrics/traffic ingest/rollups, bounded login rate limiting, and traversal-defaults PUT with the correct node-revision CAS axis. Independent fresh spec/ownership and quality/security reviews both APPROVE after two bounded repair cycles. See `.hermes/handoffs/P15-integrated.json` and `.hermes/handoffs/P15.json`.
- **P16 is integrated** (2026-09-02) at the pre-record integrated tip `329fdf5039e4e55350d923462f78c2d4ee2e3588`, cherry-picked from the reviewed candidate head `c18a3345c74be191e3d057bc1dd65517ab280e10` onto the P15 integrated tip `fa1fb739810ab8c81d0b2dbb246d5ce9a6e2c5edb` (clean, no conflict, no semantic resolution). It delivers the hooks subsystem: durable at-least-once webhook delivery queue (bounded backoff, queue-full coalesce/drop/DLQ with durable audit, decommission drop), SSRF-safe transport (resolve-validate-ALL + IP-pin preserving SNI/Host + redirect revalidation + gzip/header/body bounds), AES-256-GCM at-rest secret store with a capability-bounded broker (endpoint re-derivation, secret-to-hook binding, per-hook params allowlist, durable signature budget — never an HMAC oracle), an isolated JS runner (whitelisted runtime, bounded steps/time/memory/output, no bridge, panic-safe), an OS-isolated production runner (Linux amd64 minimum gate with dedicated non-nobody UID / net+mount namespace / empty chroot / seccomp / rlimits; fail-closed webhook-only otherwise; Windows webhook-only), and an AliDNS-style full-path fixture (no provider-specific adapter; lifecycle event only after verified durable publication). Independent fresh spec/ownership (with an independent metadata confirmation) and quality/security reviews both APPROVE after two bounded repair cycles. See `.hermes/handoffs/P16-integrated.json` and `.hermes/handoffs/P16.json`.
- P17, P18, P19 remain unstarted. P17 (web UI + deployment) is the next unblocked module and depends on P15 and P16.
- Preservation of the dirty P10 base is complete. After explicit user confirmation, only the four exact ignored generated binaries in `HANDOFF/CLEANUP_LEDGER.md` were removed (33,278,267 bytes); all other cleanup remains deferred.
- No release or remote push has been performed. P15 and P16 integration were authorized by the user's master-controller instruction; remote push remains deferred to P19.

## Plan ledger

| Plan | State at this snapshot | Evidence / qualification |
|---|---|---|
| P01 | Integrated | `5cfc6ec5331ce34fc7a713ead88ba141505b4086`; `SUPPORTED_WITH_LIMITS` |
| P02 | Integrated | `5bbfa9324270df96ef3adf4959793855c10b5c61`; `SUPPORTED_WITH_LIMITS` |
| P03 | Integrated | `05b18b11438f7e657735cc71b8566cf58833aa3f`; `SUPPORTED_WITH_LIMITS` |
| P04 | Integrated; provenance reconstructed | Implementation `770d9af988b39d02dcdc607a71068cff31ef0a94`, tree `30d821c1d954780170d96330f7b7b1bae6a2ef28`; reconstructed record is explicitly partial where historical review execution cannot be independently replayed |
| P05 | Integrated | `e2ff106afbdf81a740d557671a598576ef946a80`; `PASS` |
| P06 | Integrated | `b4edbc276138c02eaf37da015bad66979975114b`; `PASS` |
| P07 | Integrated | `231fae48f62e66e46fc53170093d543937ac7e28`; `PASS` |
| P08 | Integrated | `6ac32fdd2aeb4a2c679b3b157136a6ea714b113f`; `PASS` |
| P09 | Integrated | `7377c66a3f24a6cb6f194e839231df0b76f76544`; `PASS` |
| P10 | Integrated and independently accepted | Acceptance record at `265ad24c92719eaaf73351917622605c64f1d536`; M1 local walking skeleton passed with non-independent evidence limits |
| P11 | Integrated | `15db812553014a40cb530b6f449f80b938fdb2a8`; `SUPPORTED_WITH_LIMITS` |
| P12 | Integrated and independently accepted | Implementation `897a0f836b768296b5743f11ba32ad7ef15bce71`; acceptance/baseline `a3626376e707ffbdcdc142269dc2db6b03a2479c`; M2 `PASS_WITH_DECLARED_LIMITS` |
| P13 | Integrated | Integrated tip `9298a6c2f97c07c443ceda96b8405bc8b01f9188`; see `.hermes/handoffs/P13-integrated.json` |
| P12W | **Integrated** | Integrated tip `708931ec8667e460b73e05f741cb18a3c4b6dbe6`; closes the P12 production-composition gap; all three reviews APPROVE at `82ceec5`; see `.hermes/handoffs/P12W-integrated.json` |
| P14 | **Integrated** | `52e6922f50e3cb98ee8c2a611ee757753a73aa69`; final spec/ownership and quality/security reviews APPROVE; `SUPPORTED_WITH_LIMITS` |
| P15 | **Integrated** | `0f310193b16509d8578d011914f79af3f004c8b5`; fresh spec/ownership and quality/security reviews APPROVE after two bounded repair cycles; `SUPPORTED_WITH_LIMITS` |
| P16 | **Integrated** | `329fdf5039e4e55350d923462f78c2d4ee2e3588` (pre-record); reviewed candidate `c18a3345c74be191e3d057bc1dd65517ab280e10`; spec/ownership + quality/security APPROVE after two repair cycles; `SUPPORTED_WITH_LIMITS` |
| P17 | Unstarted | **Unblocked** (depends on P15 and P16) |
| P18 | Unstarted | Depends on P17, P14, and P08 |
| P19 | Unstarted | Depends on P01–P18 and release inputs/approval |

The P01–P12W statement is a plan-level integration ledger, not a claim that every historical record has equal evidentiary completeness. In particular, P04 provenance is reconstructed, and capability labels preserve their recorded limits.

## Milestones

| Milestone | Current status |
|---|---|
| M0 (after P04) | Technical contract/spike gate achieved; historical integrated-handoff provenance was missing from the current tree and is now reconstructed with partial-evidence labels. |
| M1 (after P10) | Passed locally with declared limits. The walking skeleton used local/loopback evidence and does not prove independent public-WAN reachability. |
| M2 (after P12) | `PASS_WITH_DECLARED_LIMITS` for reviewed libraries/adapters and declared lab evidence. `FIRST_HOP_MAPPED` was not promoted to verified. The production-composition gap that kept gateway traversal out of the Agent Forward path is now closed by P12W. |
| M3 (after P14) | `PASS_WITH_DECLARED_LIMITS`; P14 integrated at `52e6922f50e3cb98ee8c2a611ee757753a73aa69` with final independent reviews APPROVE. |
| M4 (after P15) | `SUPPORTED_WITH_LIMITS`; P15 integrated at `0f310193b16509d8578d011914f79af3f004c8b5` with fresh independent reviews APPROVE after two repair cycles. The controller API (`/api/v1`) is now a durable, reviewed operator surface; hooks (P16) integrated next, UI (P17) remains. |
| Product complete (after P17) | Not reached. |
| Platform complete (after P18) | Not reached. |
| v1.0-beta (after P19) | Not reached; no exact release digest or release approval exists. |

No milestone tags were present at inspection; these statuses are derived from reviewed handoffs and plan gates. P14's full verification limitations are recorded verbatim in `.hermes/handoffs/P14-integrated.json`.

## P12 production-wiring gap: CLOSED by P12W

P14 lifecycle integration is recorded in `.hermes/handoffs/P14-integrated.json`; P15's controller API integration is recorded in `.hermes/handoffs/P15-integrated.json`; P16's hooks subsystem integration is recorded in `.hermes/handoffs/P16-integrated.json`. P17 is the next unblocked module.

P12 added reviewed traversal components: `internal/traversal/manager.go` (`NewManager`), `internal/traversal/detection.go` (`NewDetector`), PCP/NAT-PMP/UPnP mapper packages, strategy/profile/fingerprint/journal/direct-manual/STUN-observer seams, migration `0007_traversal.sql`, and a Linux netns traversal lab. The production-composition inspection at P12 acceptance found no production call constructing `traversal.Manager`/`Detector`, no adapter registration, no bbolt `JournalStore` wiring, and no Forward creation routed through `Manager.Acquire`. `MemoryJournal` remained test-only.

P12W (plan `.hermes/plans/v1-beta/12w-production-wiring.md`; integrated record `.hermes/handoffs/P12W-integrated.json`) closes that gap in the composed Agent:

- `localstate.MappingJournal` — bbolt adapter writing the existing `mapping_journal` bucket (schema v1+; no agent schema migration).
- `New(cfg)` composes `traversal.Manager`/`Detector`, registers `pcp`/`natpmp` (default-route gateway, port 5351) and `upnp` (InterfaceIP = selection source) mappers, injects same-source STUN (`stun.NewManagerObserver`, `stun.NewSharedPortRegistry`, `stun.LeaseSource`), and preserves the accepted direct-v4 path via the shared `PortRegistry`.
- Strategy translation (`internal/agent/strategy.go`: `planFor`, `resolveForwardRoute`, `resolveAutoStrategy`) with a truthful failure surface (manual-static requires endpoint; explicit-gateway requires a resolved mapping layer; stun-only requires a STUN server; auto walks the configured `AutoOrder`, accepts only PASSED results, resolves UDP before the TCP profile, refuses missing fingerprints as stale; fixed non-direct UDP fails closed).
- Durable journal startup replay (`replayJournalBoundaries` wired into production recovery) that never resurrects fenced/tombstoned forwards and lists (never deletes) superseded/orphaned records.
- Lifecycle handlers (`traversal_lifecycle.go`) mapping Degraded/Lost/Recovered onto frozen activation axes with a mapped guard and a durable delete fence.

Repair cycles: R1 (9 findings incl. acquisition lock), R2 (auto semantics, generation fencing, same-ID serialization, bounded abandonment, cleanup retry, deletion-window fence, latent double-close), R3 (two `dataPlane.cfg` data races + closing-path hardening) are recorded in `.hermes/handoffs/P12W.json`. All three independent reviews (spec/ownership, quality/security, network/protocol) APPROVE at the reviewed head `82ceec5`.

## Evidence limits and non-claims

- No independent public-WAN evidence exists for M1 or M2.
- No real CPE/router inventory was available. P12/P12W adapter evidence used coturn and miniupnpd 2.3.4 in Linux netns; adapters retain the support level in the frozen support matrix.
- No native Windows networking runtime evidence exists for these paths. Cross-builds are compile evidence only (the STUN shared-port gate fails closed at runtime on non-Linux).
- No arm64/OpenRC platform-completion evidence, installer fresh-install/upgrade-rollback/purge evidence, or exact release-artifact evidence exists because P18/P19 have not run.
- `govulncheck` was unavailable and was recorded as skipped/unavailable, never as PASS.
- P12/P12W did not exercise a real gateway reboot or public-WAN vantage; some protocol failures are unit-scripted because the lab daemon cannot produce them.
- Same-source STUN address agreement was verified; port agreement remains daemon-specific.
- P12W known limits (D5 residual stale-window; opt-in detection job until P15; applied-bucket same-revision refresh deferred to P14; once-only `Acquisition.Release`; three non-blocking L-level nits) are recorded in `P12W-integrated.json`.
- A crash after successful map but before journal persistence may leave an unjournaled mapping; evacuation/decode of adapter `State []byte` is P14 scope.
- The current profile state cannot always distinguish “mapper not configured/not attempted” from “failed.”
- The final P14 candidate's broad full-race run had one existing `internal/controller/agenthub` receipt-test failure under whole-repository parallel load; the exact test passed in isolation at candidate and base with race x20. The broad focused package race x20 invocation timed out in the existing controller/store fairness test; isolated fairness x3 and P14-specialized controller/store race x20 passed. No DATA RACE report was observed in these limited runs; see `.hermes/handoffs/P14-integrated.json` for exact commands and exit codes.
- A pre-existing timing-sensitive `internal/agent` receipt test and `test/e2e` `TestLinuxDirectV4WalkingSkeleton` can also time out under full parallel race load; both pass in isolation and are not regression signals.

## Stop conditions

Stop rather than silently proceeding if any of the following occurs:

- A frozen contract needs reinterpretation or modification; create the required contract-change handoff and obtain approval.
- A candidate handoff is missing, malformed, dishonest, identity-mismatched, or has a failed required independent review.
- Cherry-pick/merge produces a semantic conflict; reject and rebase/re-review rather than resolving it silently in integration.
- Work would delete or alter anything outside the exact cleanup allowlist.
- Work would touch preserved historical August documents, refs, configs, archives, dirty P10 content, or non-allowlisted worktrees.
- A capability would be promoted beyond available evidence, especially WAN, router, Windows, installer, platform, or release claims.
- Release work encounters a Critical/High security finding, race, panic, unbounded growth, stale publication, deletion resurrection, secret leak, primary Linux lifecycle failure, missing exact-digest evidence, Controller payload relay, or false verified UI state.
- P14 begins before durable traversal state has a named production owner and testable composition boundary — this condition is now satisfied by the integrated P12W.

## P14 integration summary

P14 was integrated on 2026-09-01 by fast-forwarding `integration/v1-beta` from `ecdd115284c728d8b89960d8619a6d0cf69e047c` to `52e6922f50e3cb98ee8c2a611ee757753a73aa69`. The final repair-7 candidate had independent specification/ownership and quality/security APPROVE results. Its handoff records the exact full-suite and race outcomes, including the broad-run timing limitation; no failed run is represented as PASS. The integrated acceptance record is `.hermes/handoffs/P14-integrated.json`.

## P15 integration summary

P15 was integrated on 2026-09-02 by fast-forwarding `integration/v1-beta` from `d335b09f127de03254ca5119244006c41444ff0a` to `0f310193b16509d8578d011914f79af3f004c8b5`. The candidate (`ai/P15-controller-api-metrics`) went through the initial independent spec/ownership and quality/security reviews (REQUEST_CHANGES, H1-H8/M1-M4), then a bounded repair cycle 1 (implemented head `a374148`), then a repair cycle 2 (implemented head `91aab5f`) addressing the quality/security P1-A (SSE subscriber-gate data race) and P1-B (traversal-defaults permanent-412 drift) plus P2 residuals. Fresh independent spec/ownership and quality/security reviews both APPROVE at `91aab5f`. Frozen contracts remained byte-identical throughout; the combined `-race -count=10` store-package time-budget timeout (M4, pre-existing) is recorded honestly and never promoted to PASS. The integrated acceptance record is `.hermes/handoffs/P15-integrated.json`.

## P16 integration summary

P16 was integrated on 2026-09-02 by cherry-picking the candidate chain `0f310193..deb6676` (21 commits: 6 Stories, repair cycle 1 incl. the budget follow-up, repair cycle 2, and the [L] metadata correction) onto the P15 integrated tip `fa1fb739810ab8c81d0b2dbb246d5ce9a6e2c5edb`. Cherry-pick (the master plan §8.6 sanctioned method) was required because the P16 candidate base `0f31019` is the P15 *implementation* head, one commit below the P15 *integration* tip `fa1fb73` (the P15 integrated-acceptance record commit); it applied cleanly with no conflicts and no semantic resolution, and every P16-owned / serial-transfer file is byte-identical to the reviewed candidate `c18a3345c74be191e3d057bc1dd65517ab280e10`. Two bounded repair cycles preceded integration (cycle 1: P1-1 interpreter nested-return, P1-2 capability binding/durable budget/allowlist, P2-3..6, P3-7..17, plus the public secret-create budget default; cycle 2: P2-1 query-bearing hook URL rejection, P3-1..6, plus the handoff metadata [L] correction). Final fresh spec/ownership APPROVE (with an independent metadata confirmation) and final fresh quality/security APPROVE (no P1/P2). The integrated acceptance record is `.hermes/handoffs/P16-integrated.json`.

## Next decision

The next module is **P17 (web UI + deployment)** per `.hermes/plans/v1-beta/17-web-ui-deployment.md` (depends on P15 and P16, both integrated). Dispatch a coding sub-agent on `ai/P17-web-ui-deployment` in an isolated worktree from the exact current `integration/v1-beta` tip `329fdf5039e4e55350d923462f78c2d4ee2e3588`, then run fresh specification/ownership and quality/security reviews (plus UI/browser review per master plan §4.4) before integration. Remember P16's production lifecycle→webhook enqueue wiring is an explicit P17/P19 composition seam. GitHub push remains deferred to the P19 milestone.