# Next AI Handoff

## Start here

Use `/root/Claude/AntiNAT/p12-integration` as the authoritative repository.

Verify before acting:

```text
integration/P12-staging = a3626376e707ffbdcdc142269dc2db6b03a2479c
integration/v1-beta      = a3626376e707ffbdcdc142269dc2db6b03a2479c
baseline tree            = 59dec88f3249f08b76754d6d100d4ec726159f74
P13 reviewed tip         = 8f56e973722ff378881806c11e658ee8c9d96136
P13 integrated           = false
P13 integration authorized = false
preservation commit      = bcb9cdba4835e5af39d79792f3209214dd39c8cd
complete archive SHA-256 = 756bf22f12e34a2f25f23e4e123fba182a33a31ad42bbb234631e7823310d2cc
```

Read in order:

1. `docs/development/CURRENT_STATE.md`
2. `docs/development/WORKSPACE_INVENTORY.md`
3. `HANDOFF/CLEANUP_LEDGER.md`
4. `.hermes/handoffs/workspace-consolidation-2026-08-31.json`
5. `.hermes/handoffs/P04-integrated.json`
6. `.hermes/plans/v1-beta/00-master-orchestration.md`
7. `.hermes/handoffs/P12-integrated.json`
8. P13 candidate handoff from branch tip `8f56e973...` (`.hermes/handoffs/P13.json` in `/root/Claude/AntiNAT/p13-udp`) if and only if evaluating P13.

Historical August documents under `/root/Claude/AntiNAT/AntiNAT` remain historical preservation material. Do not edit them and do not use their earlier bootstrap/P10/P12 status as the current baseline.

## Current truth

- P01–P12 are integrated. P04's code is in the ancestry; its missing integrated record has been reconstructed with explicit partial-evidence qualifications.
- P10 is complete/accepted with M1 local evidence limits.
- P12 is complete/accepted at reviewed implementation and lab-evidence scope; M2 is recorded `PASS_WITH_DECLARED_LIMITS`.
- P13 is review-complete and repaired but not integrated. The final branch tip is `8f56e973722ff378881806c11e658ee8c9d96136`; its final repaired implementation is `f0cacd34c2d28a27a91411e6570c8f705bde927f`.
- P14–P19 are unstarted.
- No release or remote push has been performed.

## Open integration finding

Do not mistake P12 library/lab acceptance for a production-composition claim.

The current Agent production path does not instantiate:

- `traversal.Manager`;
- `traversal.Detector`;
- PCP/NAT-PMP/UPnP mapper registrations;
- a bbolt-backed `traversal.JournalStore` adapter.

`MemoryJournal` is an in-memory test/lab implementation and is not used in production. In fact neither it nor a durable adapter is composed because the Manager itself is not composed. The reviewed P13 candidate does not close this gap.

## Next decision required

Obtain an explicit decision on both:

1. whether/when to integrate P13; and
2. who owns the P12 production-composition gap before P14 recovery starts.

Possible ownership must be named and independently reviewed; do not silently assign it. At minimum the owned acceptance boundary must cover Manager/Detector construction, adapter and same-source STUN injection, durable bbolt journal, Forward strategy translation, recovery consumption, and route/resume/loss lifecycle behavior.

Do not begin P14 while durable traversal state and production composition have no named owner and testable boundary.

## P13 integration gate (if separately authorized)

Before integrating, revalidate exact identities, clean status, ancestry from `a362637...`, implementation/metadata separation, handoff JSON, all required review records, contract hashes, and relevant tests. Record that P13 does not close the P12 production wiring gap unless a separately reviewed change actually does so. A cherry-pick conflict is a stop condition, not permission for semantic resolution.

## Cleanup gate

Preservation is complete. After explicit user confirmation, the four exact ignored generated binaries listed in `HANDOFF/CLEANUP_LEDGER.md` were removed, reclaiming 33,278,267 bytes. No other file was deleted.

Do not run `git clean`, remove worktrees, alter refs/configs/stashes, delete archives, clean the dirty P10 worktree, or touch P13. All further cleanup is deferred.

## Evidence limits to retain

Never promote local/loopback/netns/fake-server/cross-build evidence into claims of independent WAN, real-router, native Windows, installer/platform completion, or release readiness. `govulncheck` remains unavailable/skipped in the recorded gates. P18 and P19 have not run.

## Stop conditions

Stop and escalate rather than improvise when:

- P13 integration lacks explicit authorization;
- the P12 wiring owner/boundary is still undecided at P14 start;
- a frozen contract needs change or reinterpretation;
- identity, tree, handoff, review, or contract-hash checks fail;
- integration conflicts semantically;
- an action would exceed the exact cleanup allowlist;
- an action would touch historical preservation docs, code, refs, configs, archives, dirty worktrees, or non-authorized worktrees;
- evidence cannot support the intended capability claim;
- a release input, credential, approver, or destructive remote action is required.
