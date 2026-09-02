# Next AI Handoff

## Start here

Use `/root/Claude/AntiNAT/p12-integration` as the authoritative repository.

```text
integration/v1-beta = 0f310193b16509d8578d011914f79af3f004c8b5 (P15 integrated; fast-forward, identity preserved)
P15 canonical head  = 91aab5f89b1a6b4e0d8b89294bf7f308f314619f (self-referential record commit excluded)
P15 implementation   = 91aab5f89b1a6b4e0d8b89294bf7f308f314619f
P15 integrated      = true; see .hermes/handoffs/P15-integrated.json
P16 status          = unstarted (next module; unblocked)
preservation commit = bcb9cdba4835e5af39d79792f3209214dd39c8cd
```

Read in order:

1. `docs/development/CURRENT_STATE.md`
2. `docs/development/WORKSPACE_INVENTORY.md`
3. `HANDOFF/CLEANUP_LEDGER.md`
4. `.hermes/handoffs/P12W-integrated.json`
5. `.hermes/handoffs/P12W.json` (candidate record, incl. repair_cycle_1/2/3)
6. `.hermes/handoffs/P14-integrated.json`
7. `.hermes/handoffs/P14.json` (candidate record, incl. repair_cycle_1 through repair_cycle_7)
8. `.hermes/handoffs/P15-integrated.json`
9. `.hermes/handoffs/P15.json` (candidate record, incl. repair_cycle_1 and repair_cycle_2)
10. `.hermes/plans/v1-beta/16-hooks-sandbox.md`
11. `.hermes/plans/v1-beta/00-master-orchestration.md`

Historical August documents under `/root/Claude/AntiNAT/AntiNAT` remain historical preservation material. Do not edit them and do not use their earlier bootstrap/P10/P12 status as the current baseline.

## Current truth

- P01–P15 and P12W are integrated on `integration/v1-beta`. P04's code is in the ancestry; its missing integrated record has been reconstructed with explicit partial-evidence qualifications.
- P10 is complete/accepted with M1 local evidence limits; P12 is accepted `PASS_WITH_DECLARED_LIMITS`; P13 is integrated (UDP dataplane).
- **P12W is integrated** (2026-08-31) and closes the P12 production-composition gap; see `.hermes/handoffs/P12W-integrated.json`.
- **P14 is integrated** (2026-09-01) at `52e6922f50e3cb98ee8c2a611ee757753a73aa69`, with final independent specification/ownership and quality/security reviews APPROVE. It implements deletion, decommission/cleanup-only, key rotation, backup/restore, recovery quarantine, and uninstall lifecycle. See `.hermes/handoffs/P14-integrated.json` and `.hermes/handoffs/P14.json`.
- **P15 is integrated** (2026-09-02) at `0f310193b16509d8578d011914f79af3f004c8b5`, with fresh independent specification/ownership and quality/security reviews APPROVE after two bounded repair cycles. It delivers the complete frozen Controller API, durable bounded SSE, metrics/traffic ingest, and bounded rate limiting. See `.hermes/handoffs/P15-integrated.json` and `.hermes/handoffs/P15.json`.
- P16 (hooks + sandbox) is now the next unblocked module. P17–P19 remain unstarted. No release or remote push has been performed.

## Evidence limits to retain

Never promote local/loopback/netns/fake-server/cross-build evidence into claims of independent WAN, real-router, native Windows, installer/platform completion, or release readiness. `govulncheck` remains unavailable/skipped in the recorded gates. P17–P19 have not run. P15's exact limitations, including the combined `-race -count=10` store-package time-budget timeout and the two residual P2 items (narrow concurrent-force-delete TOCTOU 500; credential-shape `value` heuristic), are recorded in `.hermes/handoffs/P15-integrated.json`; follow the `docs/development/CURRENT_STATE.md` evidence-limits section.

## Next decision

Dispatch P16 from the exact integrated tip `0f310193b16509d8578d011914f79af3f004c8b5` on branch `ai/P16-hooks-sandbox` in an isolated worktree. Follow `.hermes/plans/v1-beta/16-hooks-sandbox.md`; P16 owns hook-specific handler files serially over the frozen hook route surface (`/api/v1/hooks/definitions`, `/api/v1/hooks/secrets`, `/api/v1/hook-deliveries/{id}/retry`). Run fresh specification/ownership and quality/security reviews before integration. Do not modify frozen OpenAPI or protocol contracts without an approved contract-change handoff. Remote push remains deferred to P19.

## Stop conditions

Stop and escalate rather than improvise when:

- a frozen contract needs change or reinterpretation;
- identity, tree, handoff, review, or contract-hash checks fail;
- integration conflicts semantically;
- an action would exceed the exact cleanup allowlist;
- an action would touch historical preservation docs, code, refs, configs, archives, dirty worktrees, or non-authorized worktrees;
- evidence cannot support the intended capability claim;
- a release input, credential, approver, or destructive remote action is required.