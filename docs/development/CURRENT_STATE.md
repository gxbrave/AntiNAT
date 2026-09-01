# Current Development State

**Snapshot date:** 2026-09-01
**Authoritative repository:** `/root/Claude/AntiNAT/p12-integration`
**Authoritative baseline:** `2af27e4a4bec6bcbcb9266150a3babb317a43e4e` on `integration/v1-beta` (P14 integrated; P12W and prior P13 are in ancestry)

This document is the current consolidation view. August handoff and project-plan documents under `/root/Claude/AntiNAT/AntiNAT` remain preserved historical snapshots; do not rewrite them or treat their earlier “bootstrap-only,” “P10 blocked,” or “P12–P19 not started” statements as current status.

## Executive state

- P01–P13, P12W, and P14 are integrated into the authoritative baseline. P04's implementation is in the ancestry, but its integrated record had to be reconstructed from preserved provenance; see `.hermes/handoffs/P04-integrated.json` and its explicit evidence qualifications.
- P13 is **integrated** (2026-08-31) at integrated tip `9298a6c2f97c07c443ceda96b8405bc8b01f9188`; all P13 files byte-identical to reviewed candidate tip `8f56e973722ff378881806c11e658ee8c9d96136`. See `.hermes/handoffs/P13-integrated.json`.
- **P12W is integrated** (2026-08-31) at integrated tip `708931ec8667e460b73e05f741cb18a3c4b6dbe6`; it closes the P12 production-composition gap. See `.hermes/handoffs/P12W-integrated.json`.
- **P14 is integrated** (2026-09-01) at integrated tip `52e6922f50e3cb98ee8c2a611ee757753a73aa69`, fast-forwarded from `ecdd115284c728d8b89960d8619a6d0cf69e047c` with the approved repair-7 candidate. It delivers Forward deletion, normal/force decommission and cleanup-only gating, key rotation, backup/restore anti-rollback, recovery quarantine, and uninstall notice lifecycle. Independent final spec/ownership and quality/security reviews both APPROVE. See `.hermes/handoffs/P14-integrated.json` and `.hermes/handoffs/P14.json`.
- P15–P19 remain unstarted. P15 (Controller API, metrics, SSE, rate limiting) is now unblocked and is the next module.
- Preservation of the dirty P10 base is complete. After explicit user confirmation, only the four exact ignored generated binaries in `HANDOFF/CLEANUP_LEDGER.md` were removed (33,278,267 bytes); all other cleanup remains deferred.
- No release or remote push has been performed. P14 integration was authorized by the user's master-controller instruction; remote push remains deferred to P19.

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
| P15 | Unstarted | **Unblocked** (P14 and P06 integrated); next module in sequence |
| P16 | Unstarted | Depends on P14, P15, and P03 |
| P17 | Unstarted | Depends on P15 and P16 |
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
| Product complete (after P17) | Not reached. |
| Platform complete (after P18) | Not reached. |
| v1.0-beta (after P19) | Not reached; no exact release digest or release approval exists. |

No milestone tags were present at inspection; these statuses are derived from reviewed handoffs and plan gates. P14's full verification limitations are recorded verbatim in `.hermes/handoffs/P14-integrated.json`.

## P12 production-wiring gap: CLOSED by P12W

P14 lifecycle integration is recorded in `.hermes/handoffs/P14-integrated.json`; P15 is the next unblocked module.

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

## Next decision

The next module is **P15 (complete Controller API, metrics, SSE, rate limiting)** per `.hermes/plans/v1-beta/15-controller-api-metrics-sse.md` (depends on P14 and P06, both integrated). Dispatch a coding sub-agent on `ai/P15-controller-api-metrics` in an isolated worktree from the exact current `integration/v1-beta` tip, then run fresh specification/ownership and quality/security reviews before integration. GitHub push remains deferred to the P19 milestone.