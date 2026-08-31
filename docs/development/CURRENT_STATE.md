# Current Development State

**Snapshot date:** 2026-08-31  
**Authoritative repository:** `/root/Claude/AntiNAT/p12-integration`  
**Authoritative baseline:** `9298a6c2f97c07c443ceda96b8405bc8b01f9188` on `integration/v1-beta` (P13 integrated; prior baseline `a3626376e707ffbdcdc142269dc2db6b03a2479c` in ancestry)  
**Refs at snapshot:** `integration/v1-beta` = `9298a6c2f97c07c443ceda96b8405bc8b01f9188`; `integration/P12-staging` remains at the P12 acceptance baseline `a3626376e707ffbdcdc142269dc2db6b03a2479c`.

This document is the current consolidation view. August handoff and project-plan documents under `/root/Claude/AntiNAT/AntiNAT` remain preserved historical snapshots; do not rewrite them or treat their earlier “bootstrap-only,” “P10 blocked,” or “P12–P19 not started” statements as current status.

## Executive state

- P01–P13 are integrated into the authoritative baseline. P04's implementation is in the ancestry, but its integrated record had to be reconstructed from preserved provenance; see `.hermes/handoffs/P04-integrated.json` and its explicit evidence qualifications.
- P13 is **integrated** (2026-08-31) at integrated tip `9298a6c2f97c07c443ceda96b8405bc8b01f9188`; all P13 files byte-identical to reviewed candidate tip `8f56e973722ff378881806c11e658ee8c9d96136`. See `.hermes/handoffs/P13-integrated.json`.
- P14–P19 are unstarted and dependency-blocked.
- P12 is accepted at implementation/library and declared lab-evidence level. The current Agent production composition does not instantiate its `Manager` or `Detector`, register its PCP/NAT-PMP/UPnP adapters, or supply a durable bbolt `JournalStore` adapter. `MemoryJournal` exists for tests/labs and is not wired as a production store. **P13 integration does not close this gap**; ownership is assigned to the P12W follow-up plan before P14.
- Preservation of the dirty P10 base is complete. After explicit user confirmation, only the four exact ignored generated binaries in `HANDOFF/CLEANUP_LEDGER.md` were removed (33,278,267 bytes); all other cleanup remains deferred.
- No release or remote push is authorized by this documentation update. P13 integration was authorized by the user's master-controller instruction (develop in order, complete project, sync to GitHub).

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
| P13 | Reviewed, not integrated | Final metadata tip `8f56e973722ff378881806c11e658ee8c9d96136`; repaired implementation `f0cacd34c2d28a27a91411e6570c8f705bde927f`; four-angle review and repair-delta review PASS; integration explicitly `NOT_PERFORMED` |
| P14 | Unstarted | Blocked on P13 integration and an explicit ownership decision for the P12 production-wiring gap |
| P15 | Unstarted | Depends on P14 and P06 |
| P16 | Unstarted | Depends on P14, P15, and P03 |
| P17 | Unstarted | Depends on P15 and P16 |
| P18 | Unstarted | Depends on P17, P14, and P08 |
| P19 | Unstarted | Depends on P01–P18 and release inputs/approval |

The P01–P12 statement is a plan-level integration ledger, not a claim that every historical record has equal evidentiary completeness. In particular, P04 provenance is reconstructed, and capability labels preserve their recorded limits.

## Milestones

| Milestone | Current status |
|---|---|
| M0 (after P04) | Technical contract/spike gate achieved; historical integrated-handoff provenance was missing from the current tree and is now reconstructed with partial-evidence labels. |
| M1 (after P10) | Passed locally with declared limits. The walking skeleton used local/loopback evidence and does not prove independent public-WAN reachability. |
| M2 (after P12) | `PASS_WITH_DECLARED_LIMITS` for reviewed libraries/adapters and declared lab evidence. `FIRST_HOP_MAPPED` was not promoted to verified. Production Agent wiring remains open. |
| M3 (after P14) | Not reached. P13 is not integrated and P14 is unstarted. |
| Product complete (after P17) | Not reached. |
| Platform complete (after P18) | Not reached. |
| v1.0-beta (after P19) | Not reached; no exact release digest or release approval exists. |

No milestone tags were present at inspection; these statuses are derived from reviewed handoffs and plan gates.

## P12 production-wiring gap

P12 added reviewed traversal components, including:

- `internal/traversal/manager.go` (`NewManager`);
- `internal/traversal/detection.go` (`NewDetector`);
- PCP, NAT-PMP, and UPnP mapper packages;
- strategy, profile, fingerprint, journal, direct/manual, and STUN observer seams;
- migration `0007_traversal.sql` and a Linux netns traversal lab.

Repository-wide production-composition inspection found:

1. no production call that instantiates `traversal.Manager`;
2. no production call that instantiates `traversal.Detector`;
3. no Agent registration of PCP, NAT-PMP, or UPnP mappers in `ManagerOptions`;
4. no concrete bbolt-backed implementation wired to `traversal.JournalStore`;
5. no production call to `NewMemoryJournal` (correctly, because it is an in-memory test/lab implementation);
6. Agent data-plane composition continues to use `Assess`, `Fingerprint`, `PortRegistry`, and direct acquisition rather than routing Forward creation through `Manager.Acquire`.

The P12 candidate handoff assigned bbolt durability wiring at the Agent composition root to P13. The reviewed P13 candidate does not add the Manager, Detector, adapter registration, or durable journal adapter. Therefore P12 remains integrated and accepted for its reviewed scope, but gateway traversal is not yet reachable as a production Forward path through `antinat-agent`.

## Evidence limits and non-claims

- No independent public-WAN evidence exists for M1 or M2.
- No real CPE/router inventory was available. P12 adapter evidence used coturn and miniupnpd 2.3.4 in Linux netns; adapters retain the support level in the frozen support matrix.
- No native Windows networking runtime evidence exists for these paths. Cross-builds are compile evidence only.
- No arm64/OpenRC platform-completion evidence, installer fresh-install/upgrade-rollback/purge evidence, or exact release-artifact evidence exists because P18/P19 have not run.
- `govulncheck` was unavailable and was recorded as skipped/unavailable, never as PASS.
- P12 did not exercise a real gateway reboot or public-WAN vantage; some protocol failures are unit-scripted because the lab daemon cannot produce them.
- Same-source STUN address agreement was verified; port agreement remains daemon-specific.
- A crash after successful map but before journal persistence may leave an unjournaled mapping; recovery was deferred to P14.
- Route-change and suspend/resume monitoring do not update live acquisitions.
- `JournalRecord.OperationID` has no producer; detection-temporary mappings rely on bounded leases rather than journal persistence.
- The current profile state cannot always distinguish “mapper not configured/not attempted” from “failed.”
- P13 has strong review and test evidence but remains outside the authoritative baseline.
- P04's preserved record supports reconstruction, but historical reviewer execution and every listed runtime result were not rerun during consolidation.

## Stop conditions

Stop rather than silently proceeding if any of the following occurs:

- P13 integration is requested without explicit authorization, exact identity revalidation, and normal integration checks.
- Ownership and acceptance tests for the P12 Manager/Detector/adapters/durable-journal composition remain undefined when P14 is about to begin.
- A frozen contract needs reinterpretation or modification; create the required contract-change handoff and obtain approval.
- A candidate handoff is missing, malformed, dishonest, identity-mismatched, or has a failed required independent review.
- Cherry-pick/merge produces a semantic conflict; reject and rebase/re-review rather than resolving it silently in integration.
- Work would delete or alter anything outside the exact cleanup allowlist.
- Work would touch preserved historical August documents, refs, configs, archives, dirty P10 content, or non-allowlisted worktrees.
- A capability would be promoted beyond available evidence, especially WAN, router, Windows, installer, platform, or release claims.
- Release work encounters a Critical/High security finding, race, panic, unbounded growth, stale publication, deletion resurrection, secret leak, primary Linux lifecycle failure, missing exact-digest evidence, Controller payload relay, or false verified UI state.

## Next decision

The next human/orchestrator decision is two-part:

1. decide whether and when to authorize integration of reviewed P13 tip `8f56e973722ff378881806c11e658ee8c9d96136`; and
2. assign the P12 production-composition gap—Manager, Detector, gateway adapters, same-source STUN injection, durable bbolt journal, and recovery boundary—to a reviewed pre-P14 follow-up or an explicit P14 prerequisite.

Do not represent either decision as already made. Do not begin P14 recovery work while durable traversal state has no named production owner and testable composition boundary.
