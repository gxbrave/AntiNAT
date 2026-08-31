# Current Development State

**Snapshot date:** 2026-08-31  
**Authoritative repository:** `/root/Claude/AntiNAT/p12-integration`  
**Authoritative baseline:** `708931ec8667e460b73e05f741cb18a3c4b6dbe6` on `integration/v1-beta` (P12W integrated; prior P13 integrated tip `9298a6c2f97c07c443ceda96b8405bc8b01f9188` in ancestry)

This document is the current consolidation view. August handoff and project-plan documents under `/root/Claude/AntiNAT/AntiNAT` remain preserved historical snapshots; do not rewrite them or treat their earlier “bootstrap-only,” “P10 blocked,” or “P12–P19 not started” statements as current status.

## Executive state

- P01–P13 and P12W are integrated into the authoritative baseline. P04's implementation is in the ancestry, but its integrated record had to be reconstructed from preserved provenance; see `.hermes/handoffs/P04-integrated.json` and its explicit evidence qualifications.
- P13 is **integrated** (2026-08-31) at integrated tip `9298a6c2f97c07c443ceda96b8405bc8b01f9188`; all P13 files byte-identical to reviewed candidate tip `8f56e973722ff378881806c11e658ee8c9d96136`. See `.hermes/handoffs/P13-integrated.json`.
- **P12W is **integrated** (2026-08-31) at integrated tip `708931ec8667e460b73e05f741cb18a3c4b6dbe6`** (all candidate commits adopted by fast-forward with byte-identical identity; code tree identical to the freshly reviewed final head `82ceec5`). The **P12 production-composition gap is CLOSED**: the composed Agent now constructs `traversal.Manager`/`Detector`, registers PCP/NAT-PMP/UPnP adapters, injects same-source STUN, provides a durable bbolt `traversal.JournalStore` adapter (`localstate.MappingJournal` on the existing `mapping_journal` bucket, agent schema v3 unchanged), translates Forward strategies, replays the durable journal at startup, and wires route/resume/loss lifecycle into activation. All three independent reviews APPROVE at the final head; `P12W-integrated.json` records the gate. See `.hermes/handoffs/P12W.json` (repair_cycle_1/2/3) and `.hermes/handoffs/P12W-development-session-handoff.md`.
- P14–P19 remain unstarted. P14 (lifecycle/rotation/recovery) is the next module and is now unblocked: durable traversal state has a named production owner and a testable composition boundary.
- Preservation of the dirty P10 base is complete. After explicit user confirmation, only the four exact ignored generated binaries in `HANDOFF/CLEANUP_LEDGER.md` were removed (33,278,267 bytes); all other cleanup remains deferred.
- No release or remote push is authorized by this documentation update. P13/P12W integration was authorized by the user's master-controller instruction (develop in order, complete project, sync to GitHub).

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
| P14 | Unstarted | **Unblocked** (P12W integrated); next module in sequence |
| P15 | Unstarted | Depends on P14 and P06 |
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
| M3 (after P14) | Not reached. P14 is the next module after P12W. |
| Product complete (after P17) | Not reached. |
| Platform complete (after P18) | Not reached. |
| v1.0-beta (after P19) | Not reached; no exact release digest or release approval exists. |

No milestone tags were present at inspection; these statuses are derived from reviewed handoffs and plan gates.

## P12 production-wiring gap: CLOSED by P12W

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
- A pre-existing timing-sensitive `internal/agent` receipt test and `test/e2e` `TestLinuxDirectV4WalkingSkeleton` can time out under full parallel race load; both pass in isolation (verified at base and integrated tip) and are not regression signals.

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

## Next decision

The next module is **P14 (deletion, decommission, key rotation, backup, recovery)** per `.hermes/plans/v1-beta/14-lifecycle-rotation-recovery.md` (depends on P08, P12, P13 — all integrated; P12W cleared the pre-P14 composition requirement). Dispatch a coding sub-agent on `ai/P14-lifecycle-recovery`, then fresh-context reviews, then integrate. GitHub push remains deferred to the P19 milestone.