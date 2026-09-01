# P14 Repair Cycle 4 — lifecycle/security adversarial remediation

## Scope and starting state

This bounded cycle repairs the confirmed High/Medium lifecycle and security findings R4-1 through R4-10 (R4-11 is covered by R4-6). The candidate branch is `ai/P14-lifecycle-recovery`, starting at `ecdd115284c728d8b89960d8619a6d0cf69e047c` with canonical implementation base `973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8`. The integration branch and all other worktrees are out of scope. Use `GOWORK=off`; full tests use `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001`.

Every behavioral change follows strict RED → GREEN: add the focused regression/race/crash test, run it against the unchanged candidate and record the deterministic failure reason, then implement the minimum fix and rerun the focused test before broader verification. No frozen contract, remote, merge, push, release, or unrelated worktree is changed.

## Exhaustive allowed-file boundary

Only the following paths may be created or modified in this cycle. Any path not listed is forbidden, including all files under `internal/traversal/**`, `internal/forward/udp/**`, `test/contracts/**`, `cmd/**`, `go.mod`, `go.sum`, migrations `0001`–`0007`, and unrelated worktrees. `migrations/0008_lifecycle.sql` is additive-only (new columns/tables/indexes; no edits to prior migrations).

### Handoff/plan and lifecycle-owned paths

- `.hermes/plans/v1-beta/14-repair-4.md`
- `.hermes/handoffs/P14.json`
- `migrations/0008_lifecycle.sql`
- `internal/controller/lifecycle/rotation.go`
- `internal/controller/lifecycle/rotation_test.go`
- `internal/controller/lifecycle/recovery_authorize.go`
- `internal/controller/lifecycle/lifecycle_test.go`
- `internal/controller/agenthub/session.go`
- `internal/controller/recovery/restore.go`
- `internal/controller/recovery/restore_test.go`
- `test/integration/lifecycle_test.go`

### Controller store transfer paths (P06 → P14)

- `internal/controller/store/lifecycle.go`
- `internal/controller/store/restore.go`
- `internal/controller/store/outbox.go`
- `internal/controller/store/lifecycle_repair4_test.go`
- `internal/controller/store/migrate_test.go`

### Security transfer paths (P08 → P14)

- `internal/security/keyring.go`
- `internal/security/rotation.go`
- `internal/security/rotation_test.go`

### Agent composition/reconcile/localstate transfer paths (P07/P08/P12W → P14)

- `internal/agent/app.go`
- `internal/agent/localstate/marker.go`
- `internal/agent/localstate/recovery.go`
- `internal/agent/localstate/decommission.go`
- `internal/agent/localstate/journal.go`
- `internal/agent/localstate/lifecycle_lock_unix.go`
- `internal/agent/localstate/lifecycle_lock_windows.go`
- `internal/agent/localstate/marker_test.go`
- `internal/agent/localstate/recovery_quarantine_test.go`
- `internal/agent/localstate/decommission_test.go`
- `internal/agent/reconcile/rotation.go`
- `internal/agent/reconcile/rotation_test.go`
- `internal/agent/reconcile/decommission.go`
- `internal/agent/reconcile/decommission_test.go`
- `internal/agent/reconcile/recovery.go`
- `internal/agent/reconcile/recovery_test.go`
- `internal/agent/p14_repair4_lifecycle_test.go`

Existing tests may be amended only when one of these listed files already contains the focused coverage; otherwise the named new test files are the only new test paths permitted.

## Finding → fix → test map

### R4-1 — transactional rotation phase CAS and store FSM enforcement (HIGH)

- **Finding:** `Store.AdvanceKeyRotationPhase` unconditionally updates a row; concurrent callers can overwrite one another and direct store callers can skip/backtrack phases.
- **RED:** add `lifecycle_repair4_test.go` tests that race two callers advancing the same expected phase and assert exactly one succeeds, and call the store directly with invalid/backward/skip transitions and assert explicit invalid/conflict errors.
- **GREEN:** expose an expected/current phase CAS API (or compatible CAS variant), atomically update with `WHERE id=? AND phase=?`, enforce `PREPARED→ANNOUNCED→ACKED→ACTIVE→RETIRED` in the store, and return explicit not-found/conflict/illegal-transition errors. Keep `ForceRetireKeyRotationOperation` separate and require its documented ACKED/ACTIVE force path. Update lifecycle wrapper/callers/tests to pass expected phase.
- **Verification:** focused store/lifecycle tests plus `-race`; inspect SQL rows to prove no overwrite.

### R4-2 — rotation certificate scope, old-key identity, and structural window (HIGH)

- **Finding:** certificate decoding verifies signature and generations but accepts blank/wrong scope, forged `OldKeyID`, and malformed zero/reversed windows; agent wrapper allows blank scope.
- **RED:** add security/reconcile tests for legitimate old-key signatures with blank/wrong scope, forged old key ID, zero bounds, and deadline before not-before; all must refuse before pin persistence.
- **GREEN:** enforce the protocol’s existing controller scope literal (`controller`), require `OldKeyID == KeyIDOf(pinnedPub)`, require nonzero `NotBeforeUnix`/`OverlapDeadlineUnix` and `NotBeforeUnix <= OverlapDeadlineUnix`, and perform these checks before `SaveControllerPin`. Structural checks only; future not-before remains valid because runtime clock rejection is not contract-safe.
- **Verification:** security and reconcile package tests, including pin unchanged on refusal.

### R4-3 — controller restore reauthorization bound to operation (HIGH)

- **Finding:** `ReauthorizeNode(nodeID)` clears any quarantine without matching the active restore operation or AUTHORIZED phase.
- **RED:** add stale-operation and wrong-phase tests showing an old/unknown operation can clear a quarantined node.
- **GREEN:** additive `nodes` quarantine operation/generation binding (or equivalent durable metadata) and transactional `ReauthorizeNodeForOperation(nodeID, restoreOperationID)` requiring a current matching restore row in `AUTHORIZED` and matching node quarantine binding. Preserve old `ReauthorizeNode` only as a fail-closed wrapper that cannot bypass binding (or update all safe callers). Ensure restore entry records the operation binding for every node and finalization/reauthorization are atomic enough to prevent stale clears.
- **Verification:** store/lifecycle tests cover stale operation, wrong phase, matching operation, idempotence, and concurrent attempts.

### R4-4 — agent delayed restore result bound to current quarantine operation/generation (HIGH; supplemental B)

- **Finding:** `handleRestoreResult` ignores operation identity and current quarantine generation; an old authenticated success can clear a newer quarantine. The supplemental validator independently confirms stale restore-result binding must fail closed.
- **RED:** add delayed-result test that writes quarantine for operation A, replaces it with newer operation B, delivers authenticated success for A, and proves quarantine remains.
- **GREEN:** extend `localstate/recovery.go` payload/companion metadata with operation ID and monotonic generation/nonce; `WriteRecoveryQuarantine` records the current restore operation ID from reconcile flow. `handleRestoreReconcile` persists the binding; `handleRestoreResult` accepts only success with matching current operation/generation and expected result semantics, and rejects unknown/stale results fail-closed. Keep terminal marker precedence.
- **Verification:** localstate/reconcile/agent tests and full race suite.

### R4-5 — shared disk lock and monotonic marker/quarantine operations (HIGH; supplemental E)

- **Finding:** marker writes can downgrade DECOMMISSIONED and marker/quarantine check-then-rename/remove operations race. The supplemental validator independently confirms disk marker monotonicity and marker/quarantine atomicity.
- **RED:** add concurrent marker/quarantine tests, including DECOMMISSIONED versus DECOMMISSIONING and quarantine clear/write races; assert terminal state never downgrades or reopens. Include a non-vacuous cross-operation oracle where feasible.
- **GREEN:** add a shared process/file lock for marker and recovery files (portable project pattern), perform all load/write/clear checks under that lock, enforce monotonic marker transitions (`DECOMMISSIONED` rejects every non-terminal marker), re-check terminal state immediately before quarantine rename/remove under the same lock, fsync directory, and fail closed on lock/I/O errors. Avoid relying on P12W in-memory `App.markerMu`; disk synchronization must work cross-process.
- **Verification:** `-race` focused x20, crash/atomicity tests, and if available a cross-process lock test.

### R4-6 — per-node singleton decommission identity and reconcile latch (HIGH; covers R4-11 and supplemental A)

- **Finding:** intents/tombstones keyed by supplied operation ID allow multiple facts per node; reconcile accepts a different operation while DECOMMISSIONING. The supplemental validator calls out the same per-node intent/tombstone singleton requirement.
- **RED:** add localstate/reconcile tests for same-op idempotent retry, different-op/different-node rejection, and conflicting tombstone/intent attempts; prove no second side effect.
- **GREEN:** add durable per-node canonical identity/index using compatible bbolt key/index or transactional scan (schema version unchanged), compare complete operation+node identity before latching/side effects, allow same-op idempotence only, reject mismatches fail-closed. Ensure reconcile checks durable marker/latch before accepting commands and tombstone creation remains singleton.
- **Verification:** localstate/reconcile tests, restart/idempotence test, and race run.

### R4-7 — rotation journal intent before keyring side effect (HIGH; supplemental C duplicate)

- **Finding:** `PrepareRotation` overwrites active signer before journaling PREPARED; crash can lose old signer or leave orphan state. The supplemental validator confirms this same ordering defect; it is fixed once here, not duplicated as a separate finding.
- **RED:** add lifecycle rotation failure/crash oracle with an injected keyring activation failure/inspection showing no active-key side effect before journal intent and retries do not skip journal.
- **GREEN:** stage successor material separately, persist PREPARED operation first, then atomically activate only after journal commit; reconcile orphan/staged material on restart while preserving old signer through overlap. Keep private material out of journal/DB.
- **Verification:** focused rotation tests and a revert→FAIL→restore→PASS ordering oracle.

### R4-8 — validated exported ApplyRestore only (HIGH)

- **Finding:** exported `ApplyRestore` directly switches a database through `prepareRestoreStage`, bypassing manifest/hash/key/high-water validation.
- **RED:** add bypass regression test passing arbitrary DB/path/manifest mismatch to `ApplyRestore`; assert refusal and live DB unchanged.
- **GREEN:** make public `ApplyRestore` require a validated restore token/manifest and live store/key context and call `ValidateRestore`; keep low-level switch private or expose a clearly validated helper used by existing tests. Preserve atomic staging and restore-intent ordering.
- **Verification:** controller recovery tests, DB hash/high-water checks, and full integration recovery subset.

### R4-9 — normal rotation retire waits for deadline and all agent ACKs (HIGH; supplemental D)

- **Finding:** ACTIVE→RETIRED is allowed immediately without overlap deadline or per-node ACK tracking. The supplemental validator independently confirms future-deadline/unACKed agents must block normal retirement.
- **RED:** add tests with a future deadline/unACKed required node asserting normal retire refuses, and force-retire asserting explicit bypass only.
- **GREEN:** add additive durable per-node rotation ACK tracking/table or truthful conservative policy. Implement conservative policy if existing schema cannot enumerate requirements: normal retire refuses until overlap deadline and required ACK evidence exists; never mark RETIRED with offline/unACKed agents. Force-retire is explicit and remains atomic. Record required-agent/ACK semantics in operation/store APIs.
- **Verification:** lifecycle/store tests for deadline, ACK completion, offline/unACKed, and force path.

### R4-10 — decommission terminal marker/ACK ordering and stale-session retry (MEDIUM; supplemental F)

- **Finding:** durable DECOMMISSIONED is followed by `QueueAck(epoch=0,session="")`, which can fail stale-session; in-memory state remains DECOMMISSIONING and retry refuses terminal operation. The supplemental validator independently confirms QueueAck must use the live epoch/session (or a session-independent queue) and same-op terminal retry must be idempotent.
- **RED:** add live-session ACK failure/retry test proving durable terminal state exists while ACK fails and a same-op retry is accepted/idempotent; stale desired/rotation/restore commands remain refused.
- **GREEN:** use current session identity or a session-independent durable result queue for decommission ACK, set in-memory marker DECOMMISSIONED immediately after durable marker and before ACK, and allow same-op terminal ACK replay while rejecting different/stale operations. Preserve fail-closed behavior for non-terminal marker writes.
- **Verification:** agent lifecycle tests and full race suite.

## Required final verification and handoff

Run and record exact commands and exit codes in `.hermes/handoffs/P14.json`:

```text
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./internal/agent/localstate ./internal/agent/reconcile ./internal/controller/lifecycle ./internal/controller/recovery ./internal/security ./internal/controller/store -race -count=20
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

Record known limits honestly: no real CPE/WAN; Windows/arm64/darwin are compile-only; P15 owns operator API/restore-finalize surface; govulncheck may be unavailable; any conservative policy or API compatibility deviation is explicit. Refresh P14 top-level canonical metadata to the exact last implementation commit before the final handoff-record commit (`head_sha`, `commits[]`, `files_changed[]`), append `repair_cycle_4` with trigger/base/head/finding map/new files/verification/deviations/known flakes plus generic `verification`, explicitly list every changed/new path in `ownership_transfers`, then commit implementation coherently and commit the handoff record separately. Leave the worktree clean and stop without merge/push/release.
