# Next AI Handoff

## Start here

Use `/root/Claude/AntiNAT/p12-integration` as the authoritative repository.

```text
integration/v1-beta = 329fdf5039e4e55350d923462f78c2d4ee2e3588 (P16 integrated; cherry-picked onto the P15 integrated tip fa1fb73)
P16 review head     = c18a3345c74be191e3d057bc1dd65517ab280e10 (candidate implementation head; both final reviews APPROVE)
P16 integrated      = true; see .hermes/handoffs/P16-integrated.json
P17 status          = unstarted (next module; unblocked, depends on P15 and P16)
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
10. `.hermes/handoffs/P16-integrated.json`
11. `.hermes/handoffs/P16.json` (candidate record, incl. repair_cycle_1, repair_cycle_1_followup, repair_cycle_2)
12. `.hermes/plans/v1-beta/17-web-ui-deployment.md`
13. `.hermes/plans/v1-beta/00-master-orchestration.md`

Historical August documents under `/root/Claude/AntiNAT/AntiNAT` remain historical preservation material. Do not edit them and do not use their earlier bootstrap/P10/P12 status as the current baseline.

## Current truth

- P01–P16 and P12W are integrated on `integration/v1-beta`. P04's code is in the ancestry; its missing integrated record has been reconstructed with explicit partial-evidence qualifications.
- P10 is complete/accepted with M1 local evidence limits; P12 is accepted `PASS_WITH_DECLARED_LIMITS`; P13 is integrated (UDP dataplane).
- **P12W is integrated** (2026-08-31) and closes the P12 production-composition gap; see `.hermes/handoffs/P12W-integrated.json`.
- **P14 is integrated** (2026-09-01) at `52e6922f50e3cb98ee8c2a611ee757753a73aa69`, with final independent specification/ownership and quality/security reviews APPROVE. It implements deletion, decommission/cleanup-only, key rotation, backup/restore, recovery quarantine, and uninstall lifecycle. See `.hermes/handoffs/P14-integrated.json` and `.hermes/handoffs/P14.json`.
- **P15 is integrated** (2026-09-02), with fresh independent specification/ownership and quality/security reviews APPROVE after two bounded repair cycles. It delivers the complete frozen Controller API, durable bounded SSE, metrics/traffic ingest, and bounded rate limiting. See `.hermes/handoffs/P15-integrated.json` and `.hermes/handoffs/P15.json`.
- **P16 is integrated** (2026-09-02) at `329fdf5039e4e55350d923462f78c2d4ee2e3588`, cherry-picked from reviewed candidate head `c18a3345c74be191e3d057bc1dd65517ab280e10` onto the P15 integrated tip `fa1fb739810ab8c81d0b2dbb246d5ce9a6e2c5edb`; final fresh spec/ownership (with an independent metadata confirmation) and quality/security reviews APPROVE after two bounded repair cycles. It delivers the hooks subsystem: durable at-least-once webhook delivery queue (bounded backoff, DLQ, decommission drop), SSRF-safe transport, AES-256-GCM at-rest secrets with a capability-bounded broker (endpoint derivation, secret-to-hook binding, params allowlist, durable budget — never an HMAC oracle), isolated JS runner, OS-isolated production runner (Linux amd64 minimum gate, fail-closed webhook-only otherwise), and an AliDNS-style full-path fixture. See `.hermes/handoffs/P16-integrated.json` and `.hermes/handoffs/P16.json`.
- P17 (web UI + deployment) is now the next unblocked module, depending on P15 and P16. P18–P19 remain unstarted. No release or remote push has been performed.

## Evidence limits to retain

Never promote local/loopback/netns/fake-server/cross-build evidence into claims of independent WAN, real-router, native Windows, installer/platform completion, or release readiness. `govulncheck` remains unavailable/skipped in the recorded gates. P17–P19 have not run. P15's exact limitations (the combined `-race -count=10` store-package time-budget timeout and the two residual P2 items) are recorded in `.hermes/handoffs/P15-integrated.json`; P16's exact limitations (production lifecycle→webhook enqueue wiring is an explicit P17/P19 composition seam; signature-budget monotonic default 1024; create-time IP-literal host validation deferred; dispatcher not joined on Shutdown; govulncheck unavailable) are recorded in `.hermes/handoffs/P16-integrated.json`. Follow the `docs/development/CURRENT_STATE.md` evidence-limits section.

## Next decision

Dispatch P17 from the exact integrated tip `329fdf5039e4e55350d923462f78c2d4ee2e3588` on branch `ai/P17-web-ui-deployment` in an isolated worktree. Follow `.hermes/plans/v1-beta/17-web-ui-deployment.md`; P17 owns UI assets/routes and the deployment command surface, and per master plan §7 UI assets remain P17-only (the public navigation home + bilingual four-tab admin UI). Remember P16's P2-3 seam: production lifecycle→webhook enqueue wiring is a P17/P19 composition point consuming the P16 `EnqueueLifecycleEvent`/`MarkDecommissioned` APIs (P14/P15 lifecycle files were intentionally left untouched by P16). Run fresh specification/ownership and quality/security reviews (plus UI/browser review per master plan §4.4) before integration. Do not modify frozen OpenAPI or protocol contracts without an approved contract-change handoff. Remote push remains deferred to P19.

## Stop conditions

Stop and escalate rather than improvise when:

- a frozen contract needs change or reinterpretation;
- identity, tree, handoff, review, or contract-hash checks fail;
- integration conflicts semantically;
- an action would exceed the exact cleanup allowlist;
- an action would touch historical preservation docs, code, refs, configs, archives, dirty worktrees, or non-authorized worktrees;
- evidence cannot support the intended capability claim;
- a release input, credential, approver, or destructive remote action is required.