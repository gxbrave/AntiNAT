# P17 — Bilingual Navigation/Admin UI and Safe Deployment Command Generation Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Build the white Operate-mode public navigation and four-tab admin UI in vanilla HTML/CSS/JS, with evidence-chain state presentation, accessible interactions, SSE updates, and secret-safe deployment flow.

**Parent:** `00-master-orchestration.md`

**Dependencies:** P15 and P16 integrated.

**Wave:** W12

**Preferred model profile:** Frontend design/accessibility model plus security-aware vanilla JS implementation

---

## Owned files

- Create/own: `docs/ui-design-direction.md`
- Create/own: `web/templates/**`, `web/static/**`, `web/i18n/**`, `internal/controller/web/assets.go`
- Create/own: `internal/controller/deployment/**`, `internal/controller/api/deployment.go`
- Create/own: browser test configuration, `test/browser/**`, `scripts/test-browser.sh`
- May modify P15 router only for asset/deployment route registration after transfer

## Ownership transfer / integration notes

Must load `design-critique`, `frontend-design`, safe `impeccable`, and `make-interfaces-feel-better` in that order. P18 consumes installer fixtures. No React/Vue or second styling system.

## Explicit non-goals

No network protocol changes, local-script hook, secret in generated command, unsupported status shown as supported.

## Stories

### Story 1: Design direction and tokens
- Critique product jobs/states; create `docs/ui-design-direction.md` with Operate mode, semantic tokens and evidence-chain rail.
- Verify no color-only status and progressive disclosure for advanced NAT evidence.

### Story 2: Public home
- RED browser tests for category navigation, verified link, unverified/stale/offline risk, private-site login and mobile category strip.
- GREEN semantic templates/JS/CSS.

### Story 3: Four-tab admin shell
- RED keyboard/focus/mobile/long bilingual strings/loading/error/empty/SSE reconnect.
- GREEN Home Settings, Forwards, Nodes, Global Settings with durable state labels.

### Story 4: Node deployment flow
- RED create success/failure/double-submit, detection progress, all-failed save, Clipboard fallback.
- GREEN structured profile and platform tabs.

### Story 5: Safe command builder
- RED POSIX/PowerShell quoting, URL normalization, injection corpus, Docker option filtering, token absent from command.
- GREEN nonsecret command + separate one-time token/TTY flow.

### Story 6: Destructive dialogs
- Separate exact consequences for Forward delete, normal node delete and force delete; focus trap/return and offline pending.

### Story 7: Full browser/accessibility review
- WCAG 2.2 AA, 40/44px targets, reduced motion, tabular figures, no layout shift, Chinese/English/mobile screenshots; four-skill final critique.

## Required verification

```bash
go test ./internal/controller/deployment ./internal/controller/web ./internal/controller/api -count=1
# Run the browser framework frozen by P04, e.g. its documented test command
./scripts/test-browser.sh
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P17-web-ui` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P17.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
