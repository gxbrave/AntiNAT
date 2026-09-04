# P17 paused handoff — resume point for the next developer agent

> **Current pointer (authoritative):** implementation candidate `5af5431bdb67e1ac4f2e389d306311e0fce42ae6`; handoff metadata is in the later documentation commit `1a1d785`. The historical fields below describe the original pause only.

**Status:** `SUPERSEDED_BY_P17_CANDIDATE`

## Agents and worktree

- No live background agents remain. The P17 dev agent was stopped by the user.
- Worktree: `/root/Claude/AntiNAT/p17-web-ui`
- Branch: `ai/P17-web-ui`
- Current HEAD: `f6f05924a110835780692a8115b381f338d1a5d7`
- Required P17 base: `329fdf5039e4e55350d923462f78c2d4ee2e3588`
- Do not reset, clean, or discard the pending Story 3 files.
- Do not touch the other phase worktrees or integrate into `integration/v1-beta` from this handoff.

## Completed and committed

- `1a01ab7` — P17 Story 1: frozen UI design direction and semantic tokens.
- `f6f0592` — P17 Story 2: bilingual public home, durable risk states, category navigation, private-site gate, and Playwright browser gate.

These commits are candidate implementation commits only; they have not been independently reviewed or integrated.

## Pending working-tree changes

The following files were present at the user-requested stop and must be inspected before continuing:

```text
 M scripts/test-browser.sh
 M web/i18n/en.json
 M web/i18n/zh.json
 M web/static/css/antinat.css
 M web/static/js/admin.js
 M web/templates/admin.html
 M web/templates/home.html
?? test/browser/admin.spec.js
?? web/static/js/panes.js
?? web/static/js/ui.js
```

The stopped agent's last report was: **the hidden-overlay CSS rule is present, Story 3 files are still pending, and the admin browser gate was about to run**. No result from that run was received. Therefore do not claim Story 3 is green, committed, or reviewed.

## Resume sequence

1. Verify the worktree identity and the exact status above.
2. Read `.hermes/plans/v1-beta/17-web-ui-deployment.md`, the master orchestration role/ownership sections, and the P17 design direction before editing.
3. Inspect the pending diff. Preserve the hidden-overlay fix; do not rewrite Story 1/2.
4. Run `./scripts/test-browser.sh` first to establish the actual Story 3 baseline. Record the real exit code/output; no skipped test is a pass.
5. Finish Story 3 (four-tab admin shell) with RED → GREEN → REFACTOR, including keyboard/focus, mobile, long bilingual strings, loading/error/empty states, SSE reconnect, and text+shape durable statuses. Commit Story 3 as one coherent commit.
6. Continue Stories 4–7 in order. Keep the additive contract restriction: only the two approved deployment-profile OpenAPI paths and migration `0011_deployment.sql` may change the frozen contract surface.
7. Complete the safe command builder and deployment flow without ever putting a token/secret in a generated command. Do not add unapproved routes or modify lifecycle production wiring owned by P19.
8. Write the final `.hermes/handoffs/P17.json` and `.hermes/handoffs/P17-contract-change.md`; do not write any `*-integrated.json`.
9. Run every required gate from the P17 brief and record honest exit codes/evidence before handing off for independent review. Do not self-approve or integrate.

## State at pause (historical; superseded)

The following was true at the user-requested pause and is retained only as
provenance. Current acceptance and limits are in `.hermes/handoffs/P17.json`
and `.hermes/handoffs/P17-contract-change.md`.
- Story 3 commit and all Stories 4–7.
- Deployment package/API, structured profile persistence, additive migration/OpenAPI change, and contract-change hash record.
- Final P17 handoff JSON, screenshot evidence, and independent spec/quality/security/UI review.
- No browser result was captured after the last continuation stop; no focused, cumulative, vet, formatting, Windows compile, or OpenAPI gate result should be inferred from this checkpoint.

## Required final gates (real exit codes only)

```text
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./internal/controller/deployment ./internal/controller/web ./internal/controller/api -count=1
./scripts/test-browser.sh
python3 test/contracts/validate_openapi.py .
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./...
gofmt -l internal/
git diff --check
go vet ./...
GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/controller/deployment/...
```

`govulncheck` is unavailable in this environment; record it as unavailable rather than treating it as a pass. Browser evidence is local loopback only; do not claim real-WAN, real-router, native-Windows execution, or release readiness.

## Permission/session note

The user settings now pin `permissions.defaultMode` to `bypassPermissions` and include `/root` as an additional directory. New agents/sessions should use absolute paths within their own worktree and prefer Read/Write/Edit/Glob/Grep over shell file reads. This does not change the P17 ownership or security stop conditions.
