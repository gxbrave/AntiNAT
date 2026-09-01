# P14 Repair Cycle 1 (R1) — bounded fix spec for the two REQUEST_CHANGES reviews

> **For the repair worker:** Fix ALL spec-review and quality/security findings below
> in one bounded cycle, TDD every behavior change (RED before GREEN), keep
> `docs/recovery.md` (plan-owned) truthful per S3, do NOT touch frozen contracts,
> migrations 0001-0007, `internal/traversal/**`, `internal/forward/udp/**`,
> `test/contracts/**`, go.mod/go.sum. No merge/push; fresh reviewer contexts decide.

Branch `ai/P14-lifecycle-recovery`, base `973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8`,
HEAD `e9b78344d9bc739f7baf59c97644318cfbb472dd`. Go runs with `GOWORK=off`;
dedicated identity `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001`.

The candidate's owned files (plus declared transfers) are the ONLY production
files this cycle edits, plus the files this spec explicitly adds. Exhaustive
file boundary:

## Files I may edit (all P14-owned or declared transfers)

- Plan-owned: `docs/recovery.md`, `migrations/0008_lifecycle.sql` (additive-only;
  no ALTER needed this cycle), `internal/controller/lifecycle/**`,
  `internal/controller/recovery/**`, `internal/agent/reconcile/{delete,decommission,recovery}.go`.
- P08 transfer: `internal/security/rotation.go`, `internal/security/rotation_test.go`,
  `internal/agent/control/session.go`, `internal/security/keyring.go`.
- P06 transfer: `internal/controller/store/{lifecycle,restore,backup,outbox,minapi,probe,control}.go`.
- P12W transfer: `internal/agent/app.go`, `internal/controller/agenthub/session.go`,
  `internal/agent/reconcile/{rotation,uninstall}.go` + their tests.
- New files this cycle (all P14-owned): `internal/controller/lifecycle/recovery_authorize.go`,
  tests in `internal/controller/lifecycle/`, `internal/controller/store/`,
  `internal/agent/`, `internal/agent/reconcile/`, `internal/security/`.

Forbidden: `migrations/0001-0007`, `internal/traversal/**`, `internal/forward/udp/**`,
`test/contracts/**`, go.mod/go.sum.

## Finding → fix mapping (R1f1..R1fN)

### SPEC-REVIEW (documentary)

- **R1f1 (S1):** handoff `ownership_transfers` must explicitly name the 8 NEW files:
  P08 += `internal/security/rotation.go`, `internal/security/rotation_test.go`;
  P06 += `internal/controller/store/lifecycle.go`, `internal/controller/store/restore.go`;
  P12W/P07 += `internal/agent/reconcile/rotation.go`, `internal/agent/reconcile/rotation_test.go`,
  `internal/agent/reconcile/uninstall.go`, `internal/agent/reconcile/uninstall_test.go`.
- **R1f2 (S2):** `P14.json tests[]` `go vet` row gains `"summary":"vet clean"`.
- **R1f3 (S3):** make `docs/recovery.md` truthful.
  - Add the rotation-live check to the BACKUP path (`store.BackupToWithKeys`) so a
    backup while any rotation is non-terminal is refused (mirrors the restore
    barrier; implemented store-side as `store.EnforceRotationBarrier` since
    `store` cannot import `lifecycle`, then the doc claim at line ~71-73 is true).
  - Soften line ~93 "probe operations are invalidated" → "automatic probe dispatch
    is suspended until reauthorization" (the enqueue guard is a suspension, not an
    invalidation).
- **R1f4 (S4):** add RED-reason headers to `internal/security/rotation_test.go`,
  `internal/agent/reconcile/rotation_test.go`, `internal/agent/reconcile/uninstall_test.go`.

### HIGH / MEDIUM (must fix, TDD each behavior change)

- **R1f5 (H1):** 4 new command types unreachable over the control transport.
  `internal/agent/control/session.go` dispatch switch gains
  `case "key_rotation_prepare","key_rotation_commit","restore_reconcile","restore_result":
  return c.handleCommandOnSession(...)`. Confirm no other lifecycle type is missing
  (`node_decommission` already present). Transport test drives each new type through
  a real signed-session frame (control_test sessionHarness → hub outbox → agent
  frame → OnCommand invoked).
- **R1f6 (H2 + M3 + L4 combinable):** quarantine/cleanup dispatch gap.
  - (a) `store.AdvanceRestorePhase` gains a real caller: new
    `lifecycle.FinalizeRestore(ctx, s, operationID)` advances the restore op to
    `AUTHORIZED` so normal dispatch can resume.
  - (b) Dispatch gates on per-node quarantine AND global phase:
    `store.EnforceCleanupOnlyEnqueue` additionally refuses forbidden types when
    `IsNodeQuarantined(nodeID)`. New `store.DeliveryAllowed(nodeID, messageType)`:
    for `cleanupOnlyForbiddenTypes`, refuse when reconciling || quarantined ||
    cleanup-only; nil otherwise.
  - (c) agenthub `outboxPump` re-checks at DELIVERY time: per tick re-read
    `IsCleanupOnly` (M3a) plus reconcile/quarantine via `DeliveryAllowed`; on deny
    requeue the single item (new `store.RequeueControlOutboxItemOwned`) — fixes the
    L4 CLAIMED-strand leak and enables retry after reauthorization.
  - (a') `lifecycle.ForceDeleteNode` closes/terminates an ONLINE session: new
    `Hub.ForceCloseNodeSession(nodeID)`; `ForceDeleteNode` takes an optional
    `terminateSession ...func(nodeID string)` and invokes it after the durable
    tombstone.
  - Tests: M3 pre-tombstone session pumps zero forbidden rows after tombstone
    creation; post-tombstone `CreateForwardBundle` refuses; quarantine pump;
    reauthorize + finalize resumes dispatch.
- **R1f7 (M1):** agent anti-downgrade pin compare.
  `AcceptControllerRotationPin` must reject unless `cert.NewGeneration > pin.Generation`
  (and `cert.OldGeneration == pin.Generation`) BEFORE saving. Test: gen-4 pin +
  forged gen-1→3 cert signed by the legit gen-4 key MUST be refused.
- **R1f8 (M2):** data race on `dataPlane.recover`.
  `recover` reads `cfg.Mappers`/`cfg.Journal` from the `configSnapshot()` taken
  under `d.mu` (the snapshot copies the whole cfg; the map reference is stable
  across `rebuildTraversal` re-publication). `finishReopen` keeps using the same
  snapshot seam. Add a non-vacuous `-race` oracle test interleaving a
  Mappers re-publication with `recover` (mirrors `p12w_repair3_races_test.go`).
- **R1f9 (M4):** evacuation must retain the LIVE acquisition set.
  `EvacuateOrphanedJournals` gains a `liveRefs map[string]string` (ForwardID →
  journalID) retention input; `recover` builds it under `d.mu` and passes it.
  `finishReopen` no longer swallows the same-revision refresh error. Test: a live
  gateway forward with an empty/stale applied ref is NOT released.
- **R1f10 (M5):** decommission recover/reopen ignore the terminal latch.
  `dataPlaneConfig` gains `TerminalEngaged func() bool` (wired to `a.latch.Engaged`);
  `recover` and `finishReopen` refuse when engaged. `handleDecommission` flips
  `a.marker` to `MarkerDecommissioning` at `Begin` (not only at `Complete`), so
  `monitorLiveness`/`runDetectionOnce` stop immediately. Test: a fingerprint-change
  rebuild / cleanup-retry recover in the Begin→Complete window does NOT reopen
  applied LKG rows; DECOMMISSIONED nodes never serve again.
- **R1f11 (M6):** restore intent ordering + high-water validation.
  - (a) Write the RESTORE_RECONCILIATION intent INTO the staged DB before the
    `os.Rename` (open staged, `EnterRestoreReconciliation`, close, sync, rename) so
    a crash mid-switch can never leave a live unreconciled DB. Enter is now
    idempotent (`INSERT OR IGNORE` on restore_operations.id).
  - (b) `ValidateRestore` compares the manifest `HighWater` against the backup DB's
    actual `CurrentBackupHighWater()` (+ key set already compared) so a tampered
    backup whose contents contradict the recorded high-water is rejected.
  - Crash tests for both.

### LOW (fix all)

- **R1f12 (L1):** force-retire fast-forward writes ACTIVE then RETIRED
  non-atomically. New store `ForceRetireKeyRotationOperation` does one atomic
  `UPDATE ... SET phase='RETIRED' WHERE id=? AND phase IN ('ACKED','ACTIVE')`.
  `lifecycle.AdvanceRotationPhase` uses it. Test: force retire leaves RETIRED (no
  observable ACTIVE intermediate).
- **R1f13 (L2):** tombstone docstring vs upsert. `CreateNodeCleanupTombstone`
  rejects a second tombstone whose operation_id differs (idempotent retry of the
  SAME operation still allowed). Test both.
- **R1f14 (L3):** `_ = json.Unmarshal` on allowed_key_hashes/credential_versions
  fails SILENTLY. `NodeCleanupTombstone` and `ListCleanupTombstones` return an error
  on corrupted JSON. Test: corrupt JSON → error, not nil.
- **R1f15 (L5):** remove dead `security.signRotation`; tests call
  `SignRotationCertificate`.
- **R1f16 (L6):** `reconcile.RecoveryDeferred` must fail CLOSED on a
  `LoadRecoveryQuarantine` error: return deferred=true + `DeferredByRecoveryQuarantine`
  + error. Test: ambiguous quarantine file never auto-recovers.
- **R1f17 (L7):** `OpenBackup` validates manifest `Files[].Name` is a bare
  basename (reject `../`, absolute, empty, path separators). `ApplyRestore` bounds
  the backup DB read with a size cap (stat-based). Tests for traversal attempts and
  oversized-db refusal.

## Verification (record command + exit code in handoff repair_cycle_1)

Focused + full matrix:

```bash
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test ./... -count=1
ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./... -count=1
GOWORK=off go test ./internal/agent/localstate ./internal/agent/reconcile ./internal/controller/lifecycle ./internal/controller/recovery -race -count=20
GOWORK=off go vet ./...
GOWORK=off go test ./test/contracts -run TestContractManifest -count=1
GOWORK=off go test -tags=netns ./test/integration -run 'TestTCPTraversal|TestAgentGatewayTraversal|TestUDP' -count=1
GOWORK=off go test ./test/integration -run 'Delete|Decommission|Recovery|Rotation' -count=1 -v
GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/... ./internal/... && GOOS=linux GOARCH=arm64 ... && GOOS=darwin GOARCH=amd64 ...
gofmt -l <all changed Go files>   # empty
git diff --check
govulncheck   # record UNAVAILABLE honestly, not a gate
```

Targeted new tests: H1 transport (real frames), M2 -race oracle, M3 pump +
CreateForwardBundle, M4 live-retention, M5 Begin-window latch, M6 crash+high-water,
M1 downgrade-refused.

Known flake classes (internal/agent receipt retry, test/e2e
TestLinuxDirectV4WalkingSkeleton under parallel -race) pass in isolation — record
honestly, re-run in isolation if hit, do not chase. govulncheck UNAVAILABLE.

## Stop condition

All findings fixed or `reassert`ed with code evidence; every command recorded;
handoff `repair_cycle_1` block written; `docs/recovery.md` truthful; commits
applied per-finding. No merge, push, workflow, or frozen-contract change.