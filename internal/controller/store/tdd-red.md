# P06 TDD RED evidence — Controller store & auth

Plan: `.hermes/plans/v1-beta/06-controller-store-auth.md`
Base: `a85cb88f3b99a8f4908751f37e29d031aa44be42` (integration/v1-beta HEAD == P05 record commit)
Branch: `ai/P06-controller-store-auth`

Every story followed RED → GREEN → REFACTOR. For each story, the focused
failing test was written first and run; the captured RED reason is below,
followed by the minimal GREEN that made it pass.

## Story 1 — Migration and constraints

RED (migrate_test.go):

```
go test ./internal/controller/store/ -count=1
> github.com/gxbrave/AntiNAT/internal/controller/store: no non-test Go files
> FAIL ... [build failed]
```

`store.Open`, `SchemaVersion`, `CreateForward`, `CreateNode`,
`CreateForwardSpec`, `CreateForwardDeletionOperation`,
`GetForwardDeletionOperation`, `DeleteForwardRow`, `CASForwardActivation`
did not exist. After implementing `migrations/0001_core.sql`,
`migrations/0002_control.sql`, `migrations/migrations.go` (embedding) and the
store package, all five RED tests passed, including a NULL-scan fix for
`completed_at` (GREEN-phase fix).

## Story 2 — Transactional desired/delete/outbox

RED (transaction_test.go): `EnqueueControlOutbox`, `ControlOutboxItem`,
`ApplyForwardDesired`, `ApplyForwardDelete`, `ApplyNodeDelete`,
`ForwardSpecCount`, `ControlOutboxCount`, `NodeDeletionOperation` all
undefined → build failed. After implementing `outbox.go`, `transactions.go`
and the missing methods, the fault-injection rollback tests passed.

## Story 3 — Idempotency + durable admin events

RED (idempotency_test.go): `IdempotencyRecord`, `StoreIdempotency`,
`GetIdempotency`, `AppendAdminEvent`, `AdminEventsAfter`, `LastAdminEventID`,
`ErrIdempotencyConflict` undefined → build failed. After implementing
`idempotency.go` and `events.go`, replay/conflict/expiry/cursor-restart tests
passed.

## Story 4 — Password/session services

RED (users_test.go, auth_test.go): store user/session APIs and the whole
`internal/controller/auth` package absent → build failed ("no non-test Go
files"). After implementing `store/users.go` and `auth/password.go`,
`auth/service.go`, all round-trip/migration/expiry/revoke/no-plaintext tests
passed. One test bug (multi-value `GenerateSecret`) fixed in GREEN phase.

## Story 5 — WAL/backup/low disk

RED (backup_test.go, backup_internal_test.go): `BackupTo`, `OpenBackup`,
`InstanceID`, `DiskFreeBytes`, `SetDiskPolicy`, `ErrDiskLow`, `ForwardCount`
undefined → build failed. After implementing `backup.go`, `instance.go`,
`disk*.go` and guards, concurrent-writes+backup, instance-id stability,
real statfs, low-disk refusal and busy-wait tests passed.

## Story 6 — Corruption and migration failure

RED: the behaviours (integrity gate in `checkIntegrity`, transactional
`applyMigration`) were implemented during Story 1 GREEN, so the focused tests
passed on first run. Story 6 regression-pins those guarantees with
`corrupt_test.go` / `corrupt_internal_test.go`; this is recorded as a known
deviation from strict RED-first for this story (the guarantees pre-existed
from S1, no new production code was added).

## Portability fix (post-S5)

`make cross-build` (GOOS=windows) failed on `undefined: syscall.Statfs` in
`disk.go` → split into `disk_linux.go` (Statfs), `disk_windows.go`
(GetDiskFreeSpaceExW) and `disk_other.go` (explicit unsupported). Linux,
Windows and darwin builds now pass.

## Final verification (exact commands and exit codes)

```
go test ./internal/controller/store ./internal/controller/auth -race -count=1   # exit 0
go test ./internal/controller/store -run 'Backup|Migration|Delete|Idempotency' -count=10  # exit 0
go test ./...                                                                      # exit 0 (ANTINAT_DEDICATED_UID/GID=12001)
go test -race ./...                                                                # exit 0
go vet ./...                                                                       # exit 0
gofmt -l (all owned dirs)                                                          # clean
git diff --check                                                                   # clean
make build                                                                         # exit 0
GOOS=windows GOARCH=amd64 go build ./internal/controller/... ./migrations/        # exit 0
GOOS=darwin  GOARCH=amd64 go build ./internal/controller/...                      # exit 0
```

Note: `go test ./...` requires `ANTINAT_DEDICATED_UID=12001` and
`ANTINAT_DEDICATED_GID=12001` (provisioned antinat-sandbox identity) for
`spike/sandbox`; this is the documented P03 environmental prerequisite, not a
P06 regression.
