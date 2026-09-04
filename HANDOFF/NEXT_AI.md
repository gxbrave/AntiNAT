# Next AI Handoff

## Start here

Use `/root/Claude/AntiNAT/p12-integration` as the authoritative repository.

```text
integration/v1-beta = e8498ff08427d546d08d671c8b1d3b33a753d084 (P17 integrated; P15/P16/P17 candidate range cherry-picked cleanly)
P17 candidate      = b5040b1379126c622277a9df5381ea22ab72a7a3 (implementation); see .hermes/handoffs/P17.json
P17 integrated     = true; see .hermes/handoffs/P17-integrated.json
P18 status         = next module; base is e8498ff08427d546d08d671c8b1d3b33a753d084
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
12. `.hermes/handoffs/P17-integrated.json`
13. `.hermes/handoffs/P17.json` and `.hermes/handoffs/P17-contract-change.md`
14. `.hermes/plans/v1-beta/18-installers-platforms.md`
15. `.hermes/plans/v1-beta/17-web-ui-deployment.md`
16. `.hermes/plans/v1-beta/00-master-orchestration.md`

Historical August documents under `/root/Claude/AntiNAT/AntiNAT` remain historical preservation material. Do not edit them and do not use their earlier bootstrap/P10/P12 status as the current baseline.

## Current truth

- P01–P16 and P12W are integrated on `integration/v1-beta`. P04's code is in the ancestry; its missing integrated record has been reconstructed with explicit partial-evidence qualifications.
- P10 is complete/accepted with M1 local evidence limits; P12 is accepted `PASS_WITH_DECLARED_LIMITS`; P13 is integrated (UDP dataplane).
- **P12W is integrated** (2026-08-31) and closes the P12 production-composition gap; see `.hermes/handoffs/P12W-integrated.json`.
- **P14 is integrated** (2026-09-01) at `52e6922f50e3cb98ee8c2a611ee757753a73aa69`, with final independent specification/ownership and quality/security reviews APPROVE. It implements deletion, decommission/cleanup-only, key rotation, backup/restore, recovery quarantine, and uninstall lifecycle. See `.hermes/handoffs/P14-integrated.json` and `.hermes/handoffs/P14.json`.
- **P15 is integrated** (2026-09-02), with fresh independent specification/ownership and quality/security reviews APPROVE after two bounded repair cycles. It delivers the complete frozen Controller API, durable bounded SSE, metrics/traffic ingest, and bounded rate limiting. See `.hermes/handoffs/P15-integrated.json` and `.hermes/handoffs/P15.json`.
- **P16 is integrated** (2026-09-02) at `329fdf5039e4e55350d923462f78c2d4ee2e3588`, cherry-picked from reviewed candidate head `c18a3345c74be191e3d057bc1dd65517ab280e10` onto the P15 integrated tip `fa1fb739810ab8c81d0b2dbb246d5ce9a6e2c5edb`; final fresh spec/ownership (with an independent metadata confirmation) and quality/security reviews APPROVE after two bounded repair cycles. It delivers the hooks subsystem: durable at-least-once webhook delivery queue (bounded backoff, DLQ, decommission drop), SSRF-safe transport, AES-256-GCM at-rest secrets with a capability-bounded broker (endpoint derivation, secret-to-hook binding, params allowlist, durable budget — never an HMAC oracle), isolated JS runner, OS-isolated production runner (Linux amd64 minimum gate, fail-closed webhook-only otherwise), and an AliDNS-style full-path fixture. See `.hermes/handoffs/P16-integrated.json` and `.hermes/handoffs/P16.json`.
- **P17 is integrated** at `e8498ff08427d546d08d671c8b1d3b33a753d084`, with 35 loopback browser tests and the full integration Go/race/contract/vet/format/cross-build/OpenAPI gates passing. It delivers the bilingual Operate-mode public/admin UI, durable SSE updates, structured secret-free deployment profiles and platform command generation, ETag/CAS and tombstone-safe destructive flows. See `.hermes/handoffs/P17-integrated.json` and `.hermes/handoffs/P17.json`.
- **P18 is next** and must start from exact integrated SHA `e8498ff08427d546d08d671c8b1d3b33a753d084`. P18 remains unstarted; no release or remote push was performed.

## Evidence limits to retain

Never promote local/loopback/netns/fake-server/cross-build evidence into claims of independent WAN, real-router, native Windows, installer/platform completion, or release readiness. `govulncheck` remains unavailable/skipped in the recorded gates. P17's UI/deployment evidence is loopback/temp-store only and its installer source/image remains mutable pending P18 trust-pinned installers. P18/P19 production installer/lifecycle work has not run. P15's exact limitations (the combined `-race -count=10` store-package time-budget timeout and the two residual P2 items) are recorded in `.hermes/handoffs/P15-integrated.json`; P16's exact limitations are recorded in `.hermes/handoffs/P16-integrated.json`. Follow the `docs/development/CURRENT_STATE.md` evidence-limits section.

## Next decision

Dispatch P18 from the exact integrated tip `e8498ff08427d546d08d671c8b1d3b33a753d084` on branch `ai/P18-installers-platforms` in an isolated worktree. Follow `.hermes/plans/v1-beta/18-installers-platforms.md`; P18 owns scripts/installers, deploy/**, internal/install/**, Docker/OCI artifacts, and platform evidence. Read P17's integrated handoff first. Do not reimplement P17 UI/profile API. Keep P17's mutable installer URL/image limitation explicit and close it with signed manifest/digest evidence. Do not modify frozen OpenAPI/protocol contracts without an approved contract-change handoff. Remote push remains deferred to P19.

## Stop conditions

Stop and escalate rather than improvise when:

- a frozen contract needs change or reinterpretation;
- identity, tree, handoff, review, or contract-hash checks fail;
- integration conflicts semantically;
- an action would exceed the exact cleanup allowlist;
- an action would touch historical preservation docs, code, refs, configs, archives, dirty worktrees, or non-authorized worktrees;
- evidence cannot support the intended capability claim;
- a release input, credential, approver, or destructive remote action is required.