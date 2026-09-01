# P14 Repair Cycle 6 — rotation staging isolation and canonical evidence

## Scope, base, and discipline

This bounded repair cycle addresses confirmed R6-1 through R6-5 findings on branch `ai/P14-lifecycle-recovery`.
The clean record tip at dispatch is `28d8fbb3cc10de9a089f93b83f8379d358b8d4dd`; the canonical resolvable base remains `973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8`; the prior repair-5 implementation/content head is `28d8fbb3cc10de9a089f93b83f8379d358b8d4dd`. Use `GOWORK=off`; full tests use `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001`. Do not merge, rebase, cherry-pick, push, release, edit the integration worktree, or use a bare git stash. Frozen contracts and migrations 0001–0007 remain untouched; migration 0008 may receive additive-only changes.

Every behavioral change follows strict RED → GREEN → REFACTOR. First add a focused failing test within the allowed boundary and run it against the unchanged candidate, retaining the exact RED result; then implement the minimum fix and rerun focused and affected suites. Metadata/evidence corrections may be recorded without a behavioral RED test.

## Exhaustive allowed-file boundary

Only these paths may be created or modified in repair cycle 6:

- `.hermes/plans/v1-beta/14-repair-6.md`
- `.hermes/handoffs/P14.json`
- `internal/controller/lifecycle/rotation.go`
- `internal/controller/lifecycle/rotation_test.go`
- `internal/controller/store/lifecycle.go`
- `internal/controller/store/lifecycle_repair6_test.go`
- `internal/security/keyring.go`
- `internal/security/rotation_test.go`
- `migrations/0008_lifecycle.sql`

No frozen contract, `internal/traversal/**`, `internal/forward/udp/**`, `test/contracts/**`, `go.mod`, `go.sum`, migration 0001–0007, or `cmd/**` path may change. No `P14-integrated` handoff may be written.

## Finding → test → fix mapping

### R6-1 — multiple PREPARED rotation operations can corrupt staging during reconciliation (HIGH)

- **RED test 1:** Add a concurrent lifecycle test that starts two `PrepareRotation` calls for distinct operation IDs against one controller scope/keyring directory and proves exactly one operation is admitted while the other is refused or waits and then is refused. Assert one PREPARED row and one operation-specific staged successor; assert the old active signer remains generation 1.
- **RED test 2:** Add a reconciliation isolation test that seeds stale PREPARED operation A without its stage and a valid operation B with operation-specific staged material (using an independent scope if needed to model legacy/corrupt rows). Reconcile all rows and assert A is explicitly removed while B remains PREPARED and its exact staged material remains loadable. This test must fail against shared staging/cleanup because A cleanup removes B's stage.
- **RED test 3:** Add a store concurrency test for two same-scope nonterminal inserts and assert exactly one succeeds, proving the durable store invariant is not only a lifecycle-wrapper convention.
- **GREEN fix:** Add an operation-specific stage path/API tied to the operation ID, with safe operation-ID handling; use it for PrepareRotation and reconciliation. Cleanup removes only the matching operation's stage and never a successor belonging to another operation. Hold one shared lifecycle reservation across the reconciliation scan and all per-operation handling; use a locked helper rather than reacquiring per row. Enforce one nonterminal rotation per signing scope transactionally in the store, with an additive 0008 unique partial index plus fail-closed store checks. Keep the old signer untouched through PREPARED/reconciliation and retain existing explicit activation/overlap semantics.

### R6-2 — canonical tip delta is not handoff-only (MEDIUM)

- **Evidence correction:** Advance top-level `head_sha` to the final repair-5 implementation/content tip before the repair-6 record commit. Set `commits[]` to exact full SHAs from `git log --format=%H 973cfa60..head_sha` and `files_changed[]` to exact `git diff --name-only 973cfa60..head_sha`; include the repair-5 implementation/content commits `0670ebd` and `28d8fbb` and their production/test/docs paths.

### R6-3 — canonical ownership gaps (MEDIUM)

- **Evidence correction:** Append explicit `ownership_transfers[]` entries for `internal/agent/reconcile/delete.go`, `internal/agent/reconcile/delete_lifecycle_test.go`, `internal/agent/reconcile/recovery.go`, `internal/agent/reconcile/recovery_test.go`, and `internal/controller/lifecycle/decommission.go`. Also name every repair-6 plan, handoff, production, migration, and test path explicitly, including operation-specific staging and store/lifecycle tests.

### R6-4 — repair-4/repair-5 delta metadata is overbroad (MEDIUM)

- **Evidence correction:** Set `repair_cycle_4.new_or_changed_files` exactly to `git diff --name-only ecdd115284c728d8b89960d8619a6d0cf69e047c..14606a8e6ddbd64e8ba1787d0153014127d64ac0`. Set `repair_cycle_5.new_or_changed_files` exactly to `git diff --name-only 572423b1695c3089f50f7bde12d8945aa0dcfdc1..28d8fbb3cc10de9a089f93b83f8379d358b8d4dd`, including `0670ebd` and `28d8fbb` content changes but excluding unrelated canonical files.

### R6-5 — repair-4 focused evidence gaps (MEDIUM)

- **RED/evidence test:** Add focused tests or exact code-evidence reassertions in the allowed repair-6 test files for deadline/normal-retire ACK status, decommission different-operation identity rejection, concurrent quarantine write/clear, validated exported `ApplyRestore` bypass refusal, and terminal ACK stale-session failure/retry. Each new test/evidence entry records its RED reason and exact command; if retained existing tests cover a claim, cite exact test names and source lines in `repair_cycle_6.reassert_with_code_evidence` instead of duplicating behavior.
- **GREEN/evidence fix:** Correct only metadata/evidence statements needed to make the repair-4 claims auditable and truthful; do not broaden production scope or alter frozen behavior.

## Required verification matrix

Record exact commands, exit codes, and concise summaries in the handoff, including focused RED results where run:

```text
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./internal/agent/localstate ./internal/agent/reconcile ./internal/controller/lifecycle ./internal/controller/recovery ./internal/security ./internal/controller/store ./internal/controller/agenthub -race -count=20
GOWORK=off go test -race ./internal/controller/lifecycle -run 'Rotation|Prepared|Staged' -count=5
affected focused lifecycle/store/security tests and exact R6 evidence tests
GOWORK=off go test -race ./internal/agent -run 'Repair4|Repair5|Restore|Decommission|Marker|Rotation|Quarantine|Terminal|Journal|Uninstall|Begin' -count=5
GOWORK=off go vet ./...
GOWORK=off go test ./test/contracts -run TestContractManifest -count=1
GOWORK=off go test -tags=netns ./test/integration -run 'TestTCPTraversal|TestAgentGatewayTraversal|TestUDP' -count=1
GOWORK=off go test ./test/integration -run 'Delete|Decommission|Recovery|Rotation' -count=1 -v
GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/...
GOOS=linux GOARCH=arm64 GOWORK=off go build ./cmd/... ./internal/...
GOOS=darwin GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/...
gofmt -l <all changed Go files>
git diff --check
 govulncheck
```

Include non-vacuity/revert evidence for the R6 concurrency and staging-isolation tests where practical. Leave the worktree clean after separate implementation and handoff-record commits; do not add `P14-integrated`.
