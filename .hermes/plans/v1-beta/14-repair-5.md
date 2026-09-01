# P14 Repair Cycle 5 — lifecycle/recovery adversarial remediation

## Scope, base, and discipline

This bounded repair cycle addresses the confirmed R5-1 through R5-7 quality findings and the R5-8 through R5-11 specification/evidence findings on branch `ai/P14-lifecycle-recovery`. The repair-5 record tip is `572423b1695c3089f50f7bde12d8945aa0dcfdc1`; the canonical resolvable base remains `973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8`. The repair-4 implementation head was `14606a8e6ddbd64e8ba1787d0153014127d64ac0`, and the integration branch/worktree is out of scope.

Use `GOWORK=off`; full repository tests use `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001`. Do not merge, rebase, cherry-pick, push, release, edit another worktree, or change frozen contracts. Every behavioral story follows RED → GREEN → REFACTOR: first add a focused failing test within this boundary, run it against the unchanged candidate and retain the failure evidence, then implement the minimum fix and rerun the focused and affected suites. Metadata-only corrections may be documented without a behavioral RED test.

## Exhaustive allowed-file boundary

Only the paths below may be created or modified in repair cycle 5. Any other path is forbidden, including all of `internal/traversal/**`, `internal/forward/udp/**`, `test/contracts/**`, `cmd/**`, `go.mod`, `go.sum`, migrations `0001`–`0007`, and the integration worktree. `migrations/0008_lifecycle.sql` remains additive-only. Existing files may be amended only for the listed findings/tests; new test files must be explicitly listed below or a currently listed test file must be used.

### Handoff, plan, and documentation

- `.hermes/plans/v1-beta/14-repair-5.md`
- `.hermes/handoffs/P14.json`
- `docs/recovery.md`

### Agent composition/control transfer

- `internal/agent/app.go`
- `internal/agent/control/session.go`
- `internal/agent/control/session_test.go`
- `internal/agent/control/lifecycle_commands_transport_test.go`
- `internal/agent/p14_repair4_lifecycle_test.go`
- `internal/agent/p14_repair5_lifecycle_test.go`

### Agent localstate transfer

- `internal/agent/localstate/decommission.go`
- `internal/agent/localstate/journal.go`
- `internal/agent/localstate/journal_evacuation.go`
- `internal/agent/localstate/lifecycle_lock_unix.go`
- `internal/agent/localstate/lifecycle_lock_windows.go`
- `internal/agent/localstate/marker.go`
- `internal/agent/localstate/recovery.go`
- `internal/agent/localstate/recovery_quarantine_test.go`
- `internal/agent/localstate/store_test.go`
- `internal/agent/localstate/uninstall.go`

### Agent reconciler transfer

- `internal/agent/reconcile/decommission.go`
- `internal/agent/reconcile/decommission_test.go`
- `internal/agent/reconcile/delete.go`
- `internal/agent/reconcile/recovery.go`
- `internal/agent/reconcile/recovery_test.go`
- `internal/agent/reconcile/rotation.go`
- `internal/agent/reconcile/rotation_test.go`
- `internal/agent/reconcile/uninstall.go`
- `internal/agent/reconcile/uninstall_test.go`
- `internal/agent/reconcile/operation.go`

### Controller AgentHub transfer

- `internal/controller/agenthub/session.go`
- `internal/controller/agenthub/lifecycle_repair1_pump_test.go`
- `internal/controller/agenthub/lifecycle_repair2_pump_test.go`

### Controller lifecycle/recovery

- `internal/controller/app.go`
- `internal/controller/lifecycle/decommission.go`
- `internal/controller/lifecycle/lifecycle_test.go`
- `internal/controller/lifecycle/recovery_authorize.go`
- `internal/controller/lifecycle/rotation.go`
- `internal/controller/lifecycle/rotation_test.go`
- `internal/controller/recovery/restore.go`
- `internal/controller/recovery/restore_test.go`

### Controller store transfer

- `internal/controller/store/backup.go`
- `internal/controller/store/backup_test.go`
- `internal/controller/store/control.go`
- `internal/controller/store/corrupt_internal_test.go`
- `internal/controller/store/lifecycle.go`
- `internal/controller/store/lifecycle_repair1_internal_test.go`
- `internal/controller/store/lifecycle_repair1_test.go`
- `internal/controller/store/lifecycle_repair2_test.go`
- `internal/controller/store/lifecycle_repair4_test.go`
- `internal/controller/store/migrate_test.go`
- `internal/controller/store/minapi.go`
- `internal/controller/store/outbox.go`
- `internal/controller/store/p10_r14_migration_test.go`
- `internal/controller/store/probe.go`
- `internal/controller/store/probe_test.go`
- `internal/controller/store/restore.go`
- `internal/controller/store/lifecycle_lock_unix.go`
- `internal/controller/store/lifecycle_lock_windows.go`

### Security transfer

- `internal/security/keyring.go`
- `internal/security/rotation.go`
- `internal/security/rotation_test.go`
- `internal/security/staged_dir_unix.go`
- `internal/security/staged_dir_windows.go`

### Migration

- `migrations/0008_lifecycle.sql`

No frozen contract changes are planned. No new production package, command, migration before 0008, or out-of-bound test is authorized.

## Finding → implementation/test mapping

### R5-1 — restore-result generation zero wildcard (HIGH)

- **Finding:** `internal/agent/app.go` accepts an authenticated success with generation `0` as a wildcard, so a malformed/legacy result can clear a current quarantine.
- **RED:** extend the listed app/localstate recovery tests with a current quarantine at a nonzero generation and an authenticated success whose operation/status match but generation is omitted/zero; assert fail-closed refusal and quarantine remains. Cover malformed/missing generation as well as stale nonzero generation.
- **GREEN:** require a nonzero generation and exact equality with the durable current binding before clearing. Do not infer or default the generation. Keep terminal-marker precedence and operation identity checks.

### R5-2 — shared backup/restore/rotation reservation (HIGH)

- **Finding:** restore validation/application, backup VACUUM, and `PrepareRotation` independently check the rotation/reconciliation barrier; another operation can begin between check and side effect.
- **RED:** add a deterministic/concurrent oracle in the listed controller lifecycle/recovery/store tests that holds one operation at its side-effect boundary while attempting the other operation, and assert the shared reservation serializes them (no VACUUM or switch while rotation is reserved, and no rotation journal/staging side effect while backup/restore is reserved). Exercise both backup and restore paths where practical.
- **GREEN:** implement one process-safe controller-state reservation used by `BackupToWithKeys`, restore validation/application, and `PrepareRotation`, covering each barrier check through its side effect. Prefer a file/process lock in the controller state directory or an equivalent SQLite advisory mechanism; avoid holding a bbolt/SQLite transaction across external filesystem operations. Ensure same-store and separately opened process instances coordinate through the same lock path, release on all errors, and fail closed on lock/I/O errors. Make read-only restore validation reservation semantics explicit and ensure ApplyRestore does not validate, release, then switch without reservation.

### R5-3 — PrepareRotation durable recoverable staging (HIGH)

- **Finding:** `PrepareRotation` persists PREPARED then can fail during `Stage`, leaving a journal claiming PREPARED while successor private material is absent; no startup/retry reconciliation invokes staged activation/recovery.
- **RED:** add a failure/restart test with an injected staging failure or inaccessible keyring directory after PREPARED persistence; assert the operation is not left falsely recoverable without a durable successor, and a retry/startup reconciliation can either complete staging from durable material or explicitly mark/refuse the operation without losing the old signer. Cover old signer preservation through the failure/overlap window.
- **GREEN:** make successor staging recoverable before/with the durable operation intent, or persist exact successor private material encrypted/atomic in the operation journal. Add startup/retry reconciliation that discovers PREPARED operations and completes or safely aborts/reconciles their staging. Never replace the active signer before explicit activation; preserve old signer until activation and overlap requirements are met. Do not expose private key material plaintext in SQLite or logs.

### R5-4 — decommission intent identity on terminal paths (HIGH)

- **Finding:** `Complete` and `ReconcileDeadline` can finalize based on incoming request fields without comparing the full durable intent, allowing a stale/different operation to write terminal marker/tombstone.
- **RED:** add mismatched-operation tests in `internal/agent/reconcile/decommission_test.go` for Complete and deadline paths, varying operation ID, NodeID, force, and key versions; assert no terminal marker/tombstone/cleanup occurs and the durable intent remains authoritative.
- **GREEN:** load the persisted intent and compare the complete durable identity (operation ID, NodeID, force, key versions and any other identity-bearing fields) before every terminal write or cleanup. Reject mismatches fail-closed; same exact operation remains idempotent.

### R5-5 — decommission deadline ACK identity/error retention (HIGH)

- **Finding:** deadline ACK uses `epoch=0, session=""` and drops `RecordResult` errors, so a live control session rejects it and retry evidence is lost.
- **RED:** add a live-session test with a recording callback/client that rejects zero identity and a transient result-queue failure; assert deadline completion uses the current epoch/session or a session-independent durable queue, returns/retains the failure, and can retry without repeating terminal side effects.
- **GREEN:** thread current control-session identity through the reconcile callback, or route deadline results through a durable session-independent local queue. Surface the enqueue/record error and preserve retry state; never fabricate zero identity.

### R5-6 — uninstall online ACK identity (MEDIUM/HIGH)

- **Finding:** online uninstall ACK has the same zero epoch/session identity.
- **RED:** extend listed uninstall tests with a live client/session identity and assert QueueAck/RecordResult receives it; add failure/retry assertion if the current path is asynchronous.
- **GREEN:** use the current session identity callback or the session-independent durable queue; preserve existing terminal/uninstall idempotence and fail-closed behavior.

### R5-7 — restore quarantine equal-generation/different-op race (HIGH)

- **Finding:** generation allocation occurs outside the disk lock and equal generation with a different operation can be accepted.
- **RED:** add a concurrent localstate/app test that starts two restore reconciliations from the same binding and/or writes equal-generation different-operation bindings; assert one monotonic successor is retained, equal-generation different-operation is rejected, and stale generations cannot clear or overwrite it.
- **GREEN:** allocate and compare generation atomically under the existing shared lifecycle lock. Re-read the binding immediately before write/rename; reject equal-generation different-operation and all stale generations. Return the durable current binding to callers only after the write is committed.

### R5-8 — repair-4 metadata delta correction (MEDIUM)

- Correct `repair_cycle_4.new_or_changed_files` to exactly `git diff --name-only ecdd115284c728d8b89960d8619a6d0cf69e047c..14606a8e6ddbd64e8ba1787d0153014127d64ac0`, preserving all repair-4 evidence and the repair-4 finding map.
- Record this as metadata-only in repair cycle 5; no production behavior is implied.

### R5-9 — explicit ownership transfer names (MEDIUM)

- Refresh `ownership_transfers` with explicit entries for every repair-4 changed path and each repair-5 changed/new path, including this plan and the handoff record. Do not rely on broad-glob-only entries.

### R5-10 — focused evidence (MEDIUM)

- Record exact RED/GREEN focused tests for R5-1 through R5-7 in the repair-5 finding map and verification. If existing coverage is retained instead of amended, name the exact test and explain the code evidence.

### R5-11 — generic verification and exact metadata (MEDIUM)

- Add generic `verification` fields with `command`, `exit_code`, and `summary`; set top-level `head_sha` to the final repair-5 implementation commit (excluding the final self-referential handoff-record commit), `commits[]` to exact `git log --format=%H base..head_sha`, and `files_changed[]` to exact `git diff --name-only base..head_sha`. Add `repair_cycle_5` with trigger/base/repair base/head/finding map/new-or-changed-files/new-files-this-cycle/generic verification/deviations/known flakes. Leave `P14-integrated` untouched.

## Required verification matrix

Run and record exact exit codes, including focused RED evidence where available:

```text
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./internal/agent/localstate ./internal/agent/reconcile ./internal/controller/lifecycle ./internal/controller/recovery ./internal/security ./internal/controller/store ./internal/controller/agenthub -race -count=20
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

Include non-vacuity/revert evidence for R5-1, R5-2, R5-3, and R5-7 where practical. Known pre-existing flakes and unavailable tools must be recorded honestly, not converted to passes. Leave the worktree clean after separate implementation and handoff-record commits; do not add `P14-integrated`.
