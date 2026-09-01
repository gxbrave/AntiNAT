# P14 Repair Cycle 2 (R2) — bounded fix spec for the second-pass REQUEST_CHANGES reviews

> **For the repair worker:** Two fresh second-pass independent reviews of the
> repaired P14 candidate returned REQUEST_CHANGES on FIVE findings (M-A data
> race, L-B outbox pump spin, L-A size-bound gap on sibling files, M-B
> functional-completeness claim, spec-review handoff metadata). Fix ALL of them
> in one bounded TDD cycle (RED before GREEN, every behavior change with proof
> of failure), keep `docs/recovery.md` (plan-owned) truthful per M-B, do NOT
> touch frozen contracts, migrations 0001-0007, `internal/traversal/**`,
> `internal/forward/udp/**`, `test/contracts/**` or go.mod/go.sum. No merge,
> push, or workflow; fresh reviewer contexts decide integration.

Branch `ai/P14-lifecycle-recovery`, base `973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8`,
repair-2 start HEAD `2966115f2694cbdd87acff5920d745475da13c35` (clean). Go runs
with `GOWORK=off`; dedicated identity `ANTINAT_DEDICATED_UID=12001
ANTINAT_DEDICATED_GID=12001` for `go test` / `-race`. No bare `git stash`.

## Files I may edit (all P14-owned or declared transfers)

- Plan-owned: `docs/recovery.md`, `migrations/0008_lifecycle.sql` (additive
  only; one ADD COLUMN for the outbox denied-row backoff),
  `internal/controller/lifecycle/**`, `internal/controller/recovery/**`,
  `internal/agent/reconcile/{delete,decommission,recovery}.go`.
- P08 transfer: `internal/agent/control/session.go`, `internal/security/*`.
- P06 transfer: `internal/controller/store/{lifecycle,restore,backup,outbox,
  minapi,probe,control}.go`.
- P12W transfer: `internal/agent/app.go`, `internal/controller/agenthub/session.go`,
  `internal/agent/reconcile/{rotation,uninstall}.go` + their tests.
- New files this cycle (all P14-owned): `internal/agent/p14_repair2_marker_race_test.go`,
  `internal/controller/store/lifecycle_repair2_test.go`,
  `internal/controller/agenthub/lifecycle_repair2_pump_test.go`, plus the
  L-A refusal test additions inside existing store/recovery backup test files.

Forbidden: `migrations/0001-0007`, `internal/traversal/**`,
`internal/forward/udp/**`, `test/contracts/**`, go.mod/go.sum. `cmd/` is P10/P15
scope — M-B uses the documentary fix only (see deviations).

## Finding → fix mapping (R2f1..R2fN)

### M-A (data race, HIGH — must be permanently closed and proven)

- **R2f1:** `internal/agent/app.go` `a.marker` field: the `handleDecommission`
  writes (`:1153` DECOMMISSIONING, `:1170` DECOMMISSIONED) race the
  background-reader goroutines `reconnectControl` (`:726/:730`),
  `monitorLiveness` (`:791`) and `runDetectionOnce` (`:853`). A second-pass
  `-race` oracle (real `App.handleDecommission` while a monitorLiveness-style
  reader loop runs) produced `WARNING: DATA RACE` at 1153/1170.
  - GREEN: add `markerMu sync.RWMutex` guarding the `marker` field with
    accessors `setMarker(s)` / `currentMarker()`; convert BOTH
    `handleDecommission` writes AND every read site (`:518 :570 :726 :730 :791
    :853 :972 :975 :1296`) to the accessors. Read-side predicate
    (`marker != MarkerActive`) is preserved exactly.
  - Oracle: NEW `internal/agent/p14_repair2_marker_race_test.go` runs a real
    `a.monitorLiveness` (1 ms tick, stable route table) on a store/latch-backed
    live `App` while the same goroutine drives `a.handleDecommission`; under
    `-race` it FAILS when the guard is reverted and is clean with the mutex.
    Proof: revert → `-race` FAIL → restore → clean, recorded in the handoff.

### L-B (outbox pump claim/requeue spin, MEDIUM)

- **R2f2:** `internal/controller/store/lifecycle.go` `cleanupOnlyForbiddenTypes`
  omits `probe_outcome` and `restore_result`. A cleanup-only node can therefore
  have those rows enqueued (`QueueProbeOutcome` directly inserts its outbox row);
  `DeliveryAllowed` refuses them (cleanup-only ⇒ only `node_decommission`) and
  `RequeueControlOutboxItemOwned` resets each to PENDING every pump tick — a
  permanent PENDING→CLAIMED hot spin.
  - GREEN part 1: add `"probe_outcome": true` and `"restore_result": true` to
    `cleanupOnlyForbiddenTypes` so the ENQUEUE guard refuses them for a
    cleanup-only/tombstoned node (and, consistently, for RESTORE_RECONCILIATION
    / quarantine).
  - GREEN part 2 (no hot-spin): the pump must requeue a still-refused row with a
    bounded backoff even when the row predates the gate. Add an additive-only
    `retry_after_unix INTEGER NOT NULL DEFAULT 0` column to `control_outbox`
    under `0008_lifecycle.sql`; `RequeueControlOutboxItemOwned` sets
    `retry_after_unix = now + deniedRowBackoffSeconds`; the claim query
    (`claimControlOutbox`) selects only `PENDING AND retry_after_unix <= now`
    so a denied row quiesces instead of being re-claimed every tick.
  - Tests (RED first): `internal/controller/store/lifecycle_repair2_test.go`
    asserts (a) `EnqueueControlOutbox` refuses `probe_outcome`/`restore_result`
    for a cleanup-only node, (b) `QueueProbeOutcome` refuses for a
    cleanup-only node, (c) `RequeueControlOutboxItemOwned` schedules a future
    `RetryAfterUnix`. `internal/controller/agenthub/lifecycle_repair2_pump_test.go`
    runs the real `outboxPump` over a pre-existing refused `probe_outcome` row on
    a cleanup-only node and asserts the row CONVERGES (is never delivered, is not
    re-claimed on consecutive ticks because `RetryAfterUnix` is set in the
    future).

### L-A (size-bound gap on manifest sibling files, MEDIUM)

- **R2f3:** `internal/controller/store/backup.go` `hashAndMode` `os.ReadFile`s
  every manifest-declared sibling file with NO size cap (the 256 MiB bound at
  `restore.go` covers only controller.db read by the restore path). A
  malicious/oversized sibling file in the snapshot dir is slurped unbounded.
  - GREEN: stat each manifest-declared file in `hashAndMode` BEFORE reading and
    refuse (fail-closed) anything above the canonical bound; export the bound as
    `store.MaxBackupFileBytes` (single source of truth) and point
    `restore.prepareRestoreStage` at it too. Applies uniformly to
    `OpenBackup` / `ValidateRestore` / the backup-creation hash.
  - Test: an oversized manifest-declared file (sparse truncate, no real bytes)
    is refused by `store.OpenBackup` AND by `recovery.ValidateRestore`.

### M-B (functional-completeness claim, MEDIUM, documentary)

- **R2f4:** `internal/controller/lifecycle/recovery_authorize.go`
  `FinalizeRestore` / `ReauthorizeNode` are library surfaces with NO production
  caller (P15 owns the operator API). The system fails closed (restore gate
  stays RESTORE_RECONCILIATION; no wrong-state dispatch), but
  `docs/recovery.md` + the handoff implied dispatch resumes through an operator
  gate reachable in the shipped artifacts.
  - GREEN (documentary): reword `docs/recovery.md` restore section so it states
    truthfully the restore/reconcile machinery is code-complete and crash-safe,
    but the operator flow to advance RESTORE_RECONCILIATION→AUTHORIZED and
    reauthorize per-node quarantines is wired by P15's API; until then it
    requires direct DB/store access or a P15-provided surface. No claim that an
    in-artifact operator flow exists. Decision: a cheap controller CLI
    subcommand is NOT in P14's owned-file list (`cmd/` is P10/P15 scope), so the
    documentary fix is chosen; recorded in `deviations`.

### Spec-review (handoff metadata refresh)

- **R2f5:** `.hermes/handoffs/P14.json` top-level was authored at the
  pre-repair candidate (`head_sha=fb442b8…`, `commits[]`=9, `files_changed`=41)
  while only the nested `repair_cycle_1` was accurate. The consuming
  drift-check derives the canonical range from the top-level fields, so the
  repair-1 commits/files vanished from the canonical range.
  - GREEN: at the end of repair-2 set top-level `head_sha` to the repair-2
    final implementation head, `commits[]` to the FULL `973cfa60..<impl head>`
    list (9 story + 12 repair-1 + repair-2 commits), and `files_changed` to the
    full `git diff --name-only 973cfa60..<impl head>` set (+ the handoff itself
    noted as self-referential).

## Verification (record exact command + exit code in the repair_cycle_2 block)

```bash
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./internal/agent/localstate ./internal/agent/reconcile ./internal/controller/lifecycle ./internal/controller/recovery -race -count=20
GOWORK=off go test -race ./internal/agent -run 'Decommission|Marker|Begin|Latch|Terminal|Evacuat|Recover' -count=5   # incl. the new live-app marker race oracle
GOWORK=off go vet ./...
GOWORK=off go test ./test/contracts -run TestContractManifest -count=1
GOWORK=off go test -tags=netns ./test/integration -run 'TestTCPTraversal|TestAgentGatewayTraversal|TestUDP' -count=1
GOWORK=off go test ./test/integration -run 'Delete|Decommission|Recovery|Rotation' -count=1 -v
GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/... ; GOOS=linux GOARCH=arm64 ... ; GOOS=darwin GOARCH=amd64 ...
gofmt -l <all changed Go files>   # empty
git diff --check
govulncheck   # UNAVAILABLE -> record honestly (not a gate)
```

Include the M-A oracle proof (revert → `-race` FAIL → restore → clean) inside
the handoff `verification`. Known flake classes (internal/agent receipt retry,
test/e2e TestLinuxDirectV4WalkingSkeleton under full parallel -race) pass in
isolation — record honestly, re-run in isolation if hit, do not chase.
govulncheck UNAVAILABLE.

## Stop condition

All findings fixed or documented, every command recorded, handoff `repair_cycle_2`
block + top-level metadata refresh written, `docs/recovery.md` truthful, commits
applied per-finding TDD. No merge, push, workflow, or frozen-contract change.