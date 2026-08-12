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

## Repair cycle 1 (P06-FIX1) — RED evidence

Findings from quality/security review (t_975cd845, comment 251), fixed on
top of `b194c8e` as repair cycle 1. Each fix followed RED → GREEN.

### Q1 — `auth.VerifyPassword` panics on malformed stored hash

RED (`auth_test.go` `TestVerifyPasswordRejectsMalformedParams`, run with
`password.go` reverted to the reviewed head — i.e. the exact code the review
rejected):

```
go test ./internal/controller/auth -run TestVerifyPasswordRejectsMalformedParams -count=1 -v
panic: argon2: number of rounds too small [recovered, repanicked]
golang.org/x/crypto/argon2.deriveKey
    .../argon2/argon2.go:102
golang.org/x/crypto/argon2.IDKey(...)
    .../argon2/argon2.go:97
...auth.VerifyPassword({{0x7edf99?, 0x9f5f08?}, {0x2013fc154230?, ...}})
    internal/controller/auth/password.go:104
FAIL    github.com/gxbrave/AntiNAT/internal/controller/auth
```

RED reason: a stored hash with `t=0` reached `argon2.IDKey` unvalidated and
panicked the whole controller process on Login — the Story-6 fail-closed
violation reported by the review. (`p=0` / `p=256`-wraps-to-0 and `m` above
the cap are caught by the same validation.)

GREEN: `password.go` now validates the parsed `t`/`p`/`m` against
`argon2MinTime=1`, `argon2MinThreads=1`, `argon2MaxThreads=255` (uint8
ceiling) and `argon2MaxMemory=1<<20` (1 GiB KiB cap) before `argon2.IDKey`
and returns an actionable `auth: malformed hash parameter ...` error. All
four malformed-hash subtests pass and the round-trip/migration tests still
pass.

### Q2 — `StoreIdempotency` check-then-act race (not atomic)

RED (`store/idempotency_test.go` `TestIdempotencyConcurrentSameKeySameHash`,
`TestIdempotencyConcurrentExpiredKeyReuse`, run against the reviewed head
implementation):

```
# same key + same hash, 256 concurrent callers (timing-dependent; reproduced
# at -count=10):
go test ./internal/controller/store -run TestIdempotencyConcurrentSameKeySameHash -count=10
--- FAIL: TestIdempotencyConcurrentSameKeySameHash (0.15s)
    idempotency_test.go:225: concurrent StoreIdempotency: store: insert idempotency:
      constraint failed: UNIQUE constraint failed: api_idempotency_keys.key (1555)

# expired key reused concurrently with different hashes (deterministic):
go test ./internal/controller/store -run TestIdempotencyConcurrentExpiredKeyReuse -count=1 -v
--- FAIL: TestIdempotencyConcurrentExpiredKeyReuse (0.02s)
    idempotency_test.go:298: concurrent expired-key reuse: wins=2 conflicts=0, want exactly 1 and 1
```

RED reason: `GetIdempotency` read and the subsequent INSERT/DELETE+INSERT ran
outside one transaction, so racing callers either hard-errored on the UNIQUE
constraint (instead of the contract-mandated replay, docs/error-codes.md §4)
or both "won" an expired-key reuse (key double-spend).

GREEN: `idempotency.go` `StoreIdempotency` now wraps the whole read-check-
write in a single `BEGIN IMMEDIATE` transaction issued on a dedicated
connection (`s.db.Conn` + `ExecContext("BEGIN IMMEDIATE")`; `database/sql`
`Begin()` only issues a deferred `BEGIN`, whose stale snapshot/read→write
upgrade is exactly the unsafe pattern above). Racing callers serialize on the
write lock: one creates/reuses the row, the rest replay or get
`ErrIdempotencyConflict`. The expired-reuse audit event commits in the same
transaction. Both concurrent tests pass reliably (`-count=10`), and the
`Backup|Migration|Delete|Idempotency` stability group passes `-count=10`.

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
