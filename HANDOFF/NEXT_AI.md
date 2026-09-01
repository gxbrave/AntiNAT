# Next AI Handoff

## Start here

Use `/root/Claude/AntiNAT/p12-integration` as the authoritative repository.

```text
integration/v1-beta = 07602b7c32d98480f74b6d8c5629f4d136c84db7 (P14 integrated; fast-forward, identity preserved)
P14 canonical head  = c70be35d509491825bf93daae8dc6b8eb2248e98 (self-referential record commit excluded)
P14 implementation   = 428eb75657b8144ddcf49c8e3a32c19101eaf92d
P14 integrated      = true; see .hermes/handoffs/P14-integrated.json
P15 status          = unstarted (next module; unblocked)
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
8. `.hermes/plans/v1-beta/15-controller-api-metrics-sse.md`
9. `.hermes/plans/v1-beta/00-master-orchestration.md`

Historical August documents under `/root/Claude/AntiNAT/AntiNAT` remain historical preservation material. Do not edit them and do not use their earlier bootstrap/P10/P12 status as the current baseline.

## Current truth

- P01–P13, P12W, and P14 are integrated on `integration/v1-beta`. P04's code is in the ancestry; its missing integrated record has been reconstructed with explicit partial-evidence qualifications.
- P10 is complete/accepted with M1 local evidence limits; P12 is accepted `PASS_WITH_DECLARED_LIMITS`; P13 is integrated (UDP dataplane).
- **P12W is integrated** (2026-08-31) and closes the P12 production-composition gap; see `.hermes/handoffs/P12W-integrated.json`.
- **P14 is integrated** (2026-09-01) at `52e6922f50e3cb98ee8c2a611ee757753a73aa69`, with final independent specification/ownership and quality/security reviews APPROVE. It implements deletion, decommission/cleanup-only, key rotation, backup/restore, recovery quarantine, and uninstall lifecycle. See `.hermes/handoffs/P14-integrated.json` and `.hermes/handoffs/P14.json`.
- P15 (complete Controller API, metrics, SSE, rate limiting) is now the next unblocked module. P16–P19 remain unstarted. No release or remote push has been performed.

## Evidence limits to retain

Never promote local/loopback/netns/fake-server/cross-build evidence into claims of independent WAN, real-router, native Windows, installer/platform completion, or release readiness. `govulncheck` remains unavailable/skipped in the recorded gates. P16–P19 have not run. P14's exact limitations, including the broad race stress limitation, are recorded in `.hermes/handoffs/P14-integrated.json`; follow the `docs/development/CURRENT_STATE.md` evidence-limits section.

## Next decision

Dispatch P15 from the exact integrated tip `07602b7c32d98480f74b6d8c5629f4d136c84db7` on branch `ai/P15-controller-api-metrics` in an isolated worktree. Follow `.hermes/plans/v1-beta/15-controller-api-metrics-sse.md`; P15 owns the full Controller API, durable SSE, metrics/traffic ingest, rate limiting, and aggregate Forward limits. Run fresh specification/ownership and quality/security reviews before integration. Do not modify frozen OpenAPI or protocol contracts without an approved contract-change handoff. Remote push remains deferred to P19.

## Stop conditions

Stop and escalate rather than improvise when:

- a frozen contract needs change or reinterpretation;
- identity, tree, handoff, review, or contract-hash checks fail;
- integration conflicts semantically;
- an action would exceed the exact cleanup allowlist;
- an action would touch historical preservation docs, code, refs, configs, archives, dirty worktrees, or non-authorized worktrees;
- evidence cannot support the intended capability claim;
- a release input, credential, approver, or destructive remote action is required.