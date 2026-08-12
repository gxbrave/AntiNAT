# P07 per-Story TDD RED evidence

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent or bug-present reasons.

## Story 1 — bbolt schema and migration (fail closed)

RED command: `go test ./internal/agent/localstate/ -count=1`

RED reason: the localstate package had no store/schema symbols (feature
absent):

```
internal/agent/localstate/store_test.go:23:29: undefined: dbFile
internal/agent/localstate/store_test.go:44:16: undefined: Open
internal/agent/localstate/store_test.go:49:21: undefined: ErrSchemaTooNew
internal/agent/localstate/store_test.go:74:16: undefined: WithLockTimeout
internal/agent/localstate/store_test.go:111:9: undefined: migration
internal/agent/localstate/store_test.go:114:15: undefined: migrate
internal/agent/localstate/store_test.go:114:27: undefined: SchemaVersion
```

GREEN: `Open` fails closed on an unknown future schema (ErrSchemaTooNew), a
corrupt database, and lock contention (bounded bolt.Open timeout); the
migration runner applies each version in its own transaction so a failing
migration leaves the previous schema and all data intact. The full frozen
bucket set (v0.8 §9.2) is created by schema v1.

## Story 2 — received desired vs applied state (PARTIAL)

RED command: `go test ./internal/agent/localstate/ -count=1`

RED reason: undefined apply symbols (feature absent):

```
internal/agent/localstate/applied_test.go:41:23: store.CommitDesired undefined
internal/agent/localstate/applied_test.go:41:45: undefined: ForwardApply
internal/agent/localstate/applied_test.go:42:33: undefined: ApplyApplied
internal/agent/localstate/applied_test.go:45:36: undefined: ApplyStatusFull
internal/agent/localstate/applied_test.go:118:25: store.GetAppliedState undefined
```

GREEN: `CommitDesired` atomically persists the received desired snapshot plus
per-Forward decisions; one Forward's apply failure retains its old applied
record while siblings advance (PARTIAL), a snapshot that merely omits a
Forward never deletes it, ABSENT deletes write a durable tombstone and remove
the applied record in the same transaction, and an invalid outcome fails the
whole commit closed.

## Story 3 — durable inbox/outbox journals

RED command: `go test ./internal/agent/localstate/ -count=1`

RED reason: undefined journal symbols (feature absent):

```
internal/agent/localstate/journal_test.go:21:18: store.AdvanceSession undefined
internal/agent/localstate/journal_test.go:24:68: undefined: ErrStaleSession
internal/agent/localstate/journal_test.go:72:158: undefined: ErrMessageConflict
internal/agent/localstate/journal_test.go:97:81: undefined: ErrIllegalPhase
internal/agent/localstate/journal_test.go:245:20: store.RequeueOutboxForSession undefined
```

GREEN: epoch/session fencing (lower epoch and same-epoch different session
rejected), message dedup (same ID+type+hash cached duplicate; same ID with
different material ErrMessageConflict), the inbox FSM
RECEIVED->INTENT_PERSISTED->APPLYING->APPLIED|NACKED with exact-predecessor
transitions, the outbox FSM PENDING->CLAIMED->SENT->SEMANTIC_ACKED->RECEIPTED
(GC), stale-writer and receipt-resurrection fencing, and result resend on a
new session via `RequeueOutboxForSession` (old-epoch ACK rejected; the same
semantic result is re-enveloped without repeating the side effect).

## Story 4 — Forward tombstones

RED command: `go test ./internal/agent/localstate/ -count=1`

RED reason: undefined tombstone symbols (feature absent):

```
internal/agent/localstate/tombstone_test.go:51:22: undefined: ErrTombstonedForward
internal/agent/localstate/tombstone_test.go:111:18: store.GCForwardTombstone undefined
```

GREEN: CommitDesired refuses to re-apply a tombstoned Forward
(ErrTombstonedForward), deletion commits are atomic under failure, tombstone
GC requires the deletion operation's durable receipt (ErrTombstoneNotGCReady
before it), and tombstones survive reopen.

## Story 5 — terminal marker and latch

RED command: `go test ./internal/agent/localstate/ -count=1`

RED reason: undefined marker/latch symbols (feature absent):

```
internal/agent/localstate/marker_test.go:17:12: undefined: WriteMarker
internal/agent/localstate/marker_test.go:17:29: undefined: MarkerDecommissioning
internal/agent/localstate/marker_test.go:20:42: undefined: markerFile
internal/agent/localstate/marker_test.go:91:11: undefined: NewLatch
internal/agent/localstate/marker_test.go:102:58: undefined: ErrTerminalEngaged
```

GREEN: the terminal marker is written temp-file + fsync + rename +
parent-directory fsync with mode 0600 (no torn markers, no leftover temps),
unknown marker content fails closed, and the exclusive latch refuses to
register any new actor after engagement (first engagement wins, never
reopens).

## Story 6 — actor isolation

RED command: `go test ./internal/agent/reconcile/ -count=1`

RED reason: undefined supervisor symbols (feature absent):

```
internal/agent/reconcile/actor_test.go:16:16: undefined: NewSupervisor
internal/agent/reconcile/actor_test.go:64:25: undefined: ActorPanicked
internal/agent/reconcile/actor_test.go:67:51: undefined: ErrActorPanicked
internal/agent/reconcile/actor_test.go:100:30: undefined: WithMaxConcurrentActors
internal/agent/reconcile/actor_test.go:116:128: undefined: ErrSupervisorFull
```

GREEN: a panicking actor is recovered and reported as ActorPanicked while
siblings complete and the supervisor survives; run failures, start-timeout
failures, and a bounded max-concurrent-actors limit are all enforced and
reported on the Results channel.

## Reconcile layer — desired/operation/reconciler

RED command: `go test ./internal/agent/reconcile/ -count=1`

RED reason: undefined reconcile symbols (feature absent):

```
internal/agent/reconcile/desired_test.go:58:17: undefined: ApplyDesired
internal/agent/reconcile/desired_test.go:85:20: undefined: OutcomeFailed
internal/agent/reconcile/operation_test.go:20:12: undefined: RecordResult
internal/agent/reconcile/operation_test.go:37:12: undefined: HandleDurableReceipt
internal/agent/reconcile/reconciler_test.go:23:16: undefined: New
internal/agent/reconcile/reconciler_test.go:77:21: undefined: ErrDecommissioned
```

GREEN: `ApplyDesired` reproduces PARTIAL semantics through the reconcile layer
(old-revision skip, tombstone no-resurrect, latch no-new-actor,
tombstone-before-stop ordering, stop-failure keeps the tombstone);
`operation.go` records results, applies durable receipts, and requeues results
on a new session; `Reconciler.ReconcileOnce` applies desired and records
durable deletion results for the current session (skipped without a session),
refuses DECOMMISSIONED (ErrDecommissioned), and `Run` is a panic-isolated
control loop that survives actor panics and exits on cancel.

## Crash matrix (VERIFY, not a new behavior story)

The crash harness (`crash_test.go`) re-executes the test binary and exits hard
at each durable-state phase. It regression-pins the invariants already built
in Stories 2/4/5 GREEN and, like P06 Story 6, passed on first run by
construction: partial-apply-before/after atomic recovery, delete
tombstone-before-stop never resurrecting after a crash, the DECOMMISSIONING
marker surviving a crash with no torn temp files, and the durable receipt
tombstone surviving a crash with no outbox resurrection. This is a documented
deviation from strict RED-first for these verification tests only.

## Required verification (final)

```bash
go test ./internal/agent/localstate ./internal/agent/reconcile -race -count=10
```
