# Next AI Handoff

## Start here

Use `/root/Claude/AntiNAT/p12-integration` as the authoritative repository.

```text
integration/v1-beta = 708931ec8667e460b73e05f741cb18a3c4b6dbe6 (P12W integrated; fast-forward, identity preserved)
P12W reviewed head  = 82ceec57a71efe839838f12e0178be41d9adade5 (code tree identical to integrated tip)
P12W integrated     = true
P14 status          = unstarted (next module; unblocked)
preservation commit = bcb9cdba4835e5af39d79792f3209214dd39c8cd
```

Read in order:

1. `docs/development/CURRENT_STATE.md`
2. `docs/development/WORKSPACE_INVENTORY.md`
3. `HANDOFF/CLEANUP_LEDGER.md`
4. `.hermes/handoffs/P12W-integrated.json`
5. `.hermes/handoffs/P12W.json` (candidate record, incl. repair_cycle_1/2/3)
6. `.hermes/handoffs/P12W-development-session-handoff.md`
7. `.hermes/plans/v1-beta/00-master-orchestration.md`

Historical August documents under `/root/Claude/AntiNAT/AntiNAT` remain historical preservation material. Do not edit them and do not use their earlier bootstrap/P10/P12 status as the current baseline.

## Current truth

- P01–P13 and P12W are integrated on `integration/v1-beta`. P04's code is in the ancestry; its missing integrated record has been reconstructed with explicit partial-evidence qualifications.
- P10 is complete/accepted with M1 local evidence limits; P12 is accepted `PASS_WITH_DECLARED_LIMITS`; P13 is integrated (UDP dataplane).
- **P12W is integrated** (2026-08-31): the P12 production-composition gap is CLOSED — the composed Agent now builds `traversal.Manager`/`Detector`, registers PCP/NAT-PMP/UPnP adapters, injects same-source STUN, uses a durable bbolt `JournalStore` adapter (`localstate.MappingJournal`), translates Forward strategies, replays the journal at startup, and wires route/resume/loss lifecycle into activation. All three independent reviews (spec/ownership, quality/security, network/protocol) APPROVE at `82ceec5`; the full verification matrix was re-recorded at that head (all exit codes 0). See `.hermes/handoffs/P12W-integrated.json`, `.hermes/handoffs/P12W.json`, and the dev-session handoff doc.
- P14 (lifecycle/rotation/recovery) is **unstarted** and is the next module — it is unblocked now that durable traversal state has a named production owner and testable composition boundary.
- P15–P19 are unstarted. No release or remote push has been performed.

## Evidence limits to retain

Never promote local/loopback/netns/fake-server/cross-build evidence into claims of independent WAN, real-router, native Windows, installer/platform completion, or release readiness. `govulncheck` remains unavailable/skipped in the recorded gates. P18 and P19 have not run. P14 must follow the `docs/development/CURRENT_STATE.md` evidence-limits section.

## Stop conditions

Stop and escalate rather than improvise when:

- a frozen contract needs change or reinterpretation;
- identity, tree, handoff, review, or contract-hash checks fail;
- integration conflicts semantically;
- an action would exceed the exact cleanup allowlist;
- an action would touch historical preservation docs, code, refs, configs, archives, dirty worktrees, or non-authorized worktrees;
- evidence cannot support the intended capability claim;
- a release input, credential, approver, or destructive remote action is required.