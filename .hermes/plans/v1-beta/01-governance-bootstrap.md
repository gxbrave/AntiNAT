# P01 — Governance, Repository, Toolchain, and CI Bootstrap Coding Plan

> **For the Coding AI:** Implement only this plan. You are an isolated implementation worker, not the project orchestrator. Do not broaden scope or self-approve integration.

**Goal:** Create the clean-room repository foundation, freeze product scope inputs, initialize Go only with the final module path, and provide executable CI/evidence skeletons.

**Parent:** `00-master-orchestration.md`

**Dependencies:** `.hermes/handoffs/project-inputs.json` with non-placeholder module path and owner.

**Wave:** W0

**Preferred model profile:** General Go/repository model with licensing and CI supply-chain awareness

---

## Owned files

- Create/own: `LICENSE`, `README.md`, `.gitignore`, `go.mod`, `go.sum`, `Makefile`
- Create/own: `docs/requirements-traceability.md`, `docs/v1-scope-contract.md`, `docs/support-matrix.md`, `docs/adr/0001-*.md` through `0004-*.md`
- Create/own: `.github/workflows/ci.yml`, `test/evidence/schema.json`, `scripts/verify-evidence.go`, `internal/buildinfo/*`, `cmd/antinat-controller/main.go`, `cmd/antinat-agent/main.go`

## Ownership transfer / integration notes

P04 later owns protocol/state/API contract docs. P18 may extend CI with platform jobs; it must not rewrite P01 scope decisions.

## Explicit non-goals

No network listeners, DB schema, enrollment, UI, installers, or traversal code.

## Stories

### Story 1: Scope and clean-room baseline
- RED: write a validation checklist/test that fails while license, module path, scope differences, Natter attribution, and support statuses are absent.
- GREEN: create Apache-2.0 license, traceability, v1 scope, support matrix, ADRs, README clean-room statement.
- VERIFY: `git diff --check`; validation reports no placeholder except explicitly deferred hardware inputs.
- Commit: `docs: freeze AntiNAT beta scope and provenance`.

### Story 2: Go module and build info
- RED: add `internal/buildinfo/buildinfo_test.go` for version/commit/date injection and two `version` commands.
- GREEN: initialize the approved module path and minimal binaries; do not start networking.
- VERIFY: focused test, `go test ./...`, Linux/Windows cross-build.
- Commit: `chore: initialize Go module and build metadata`.

### Story 3: Evidence validator
- RED: fixtures with missing SHA, command, result, or digest must fail.
- GREEN: implement JSON schema and `scripts/verify-evidence.go` validation.
- VERIFY: good fixture passes; each malformed fixture fails with stable code.
- Commit: `test: add machine-readable evidence validation`.

### Story 4: CI skeleton
- RED: local workflow-policy test rejects unpinned actions, missing timeouts, or privileged jobs on fork PRs.
- GREEN: create pr-fast/pr-integration/windows-pr skeleton with SHA-pinned actions and artifact retention.
- VERIFY: YAML parse/policy tests and local Go checks.
- Commit: `ci: establish AntiNAT quality lanes`.

## Required verification

```bash
go test ./...
go vet ./...
GOOS=windows GOARCH=amd64 go build ./cmd/...
go run ./scripts/verify-evidence.go ./test/evidence/fixtures/pass.json
```


## Common execution protocol

1. Read this child plan, `00-master-orchestration.md`, the reviewed v0.8 plan, and all dependency handoffs.
2. Confirm the exact base SHA is the orchestrator's latest integrated dependency SHA.
3. Work only on branch `ai/P01-governance-bootstrap` in an isolated worktree.
4. Edit only declared owned files. Frozen contract changes require a proposal; do not edit them silently.
5. Apply strict RED→GREEN→REFACTOR per Story. Capture the RED reason and all final commands.
6. Do not merge, push, release, or modify another child's branch.
7. Write `.hermes/handoffs/P01.json` using the master schema.
8. Stop after producing candidate commits and handoff. Fresh reviewer contexts decide integration.

## Completion gate

- Focused tests pass.
- Affected package tests pass.
- Required cumulative tests pass.
- No undeclared files changed.
- No secrets/test credentials in diff or logs.
- Handoff lists exact base/head SHAs, commands, evidence, limits, and cleanup.
