# Formal Review 2/4 — QUALITY/SECURITY

- Candidate: C3 = commit 256c91046a00c6c18a43facf1f6ff73b576f3b23 / tree 576a3d683ee78cbacba427a6055a2a925a2d8725
- Reviewed at: metadata tip 676c6b60a8431ead4a3820a5830843526ecffdab (tree c34f55d1c62d7c9686175739ecc0d1e6621c9986)
- Reviewer: independent agent, read-only
- First attempt: FAIL at identity gate (same mandate contradiction). Resumed under corrected protocol; substantive review completed.

## Verified identity

```
declared review state (metadata tip): HEAD  = 676c6b60a8431ead4a3820a5830843526ecffdab   == expected
candidate C3 tree:                    tree  = 576a3d683ee78cbacba427a6055a2a925a2d8725   == expected
```

- (1) `git rev-parse HEAD` = `676c6b6...` — matches.
- (2) `git rev-parse 256c9104...^{tree}` = `576a3d68...` — matches.
- (3) `git status --porcelain` — empty.
- (4) `git diff --name-only 256c9104 HEAD` lists **only** `.hermes/handoffs/P10-r16q2-superseding.json` and `.hermes/handoffs/P10.json` — verified directly, both under `.hermes/handoffs/`.
- Byte-identity independently confirmed per file via `git rev-parse 256c9104:<path>` vs `git hash-object` for all six reviewed files — all `IDENTICAL`; tree-wide non-`.hermes/handoffs` delta is empty.
- Lineage handoff read at HEAD: `.hermes/handoffs/P10-r16q2-superseding.json:22-26, :32, :314-315` pins C3 exactly.

## Test / gofmt / manifest results actually run

- **Focused suites (real, exit 0):** `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./internal/agent/... ./test/e2e/harness -count=1` → `ok internal/agent 4.231s`, `ok .../control 5.307s`, `ok .../localstate 2.742s`, `ok .../reconcile 4.858s`, `ok .../test/e2e/harness 1.161s`, `TEST_EXIT=0`.
- **gofmt:** `gofmt -l` over all 10 changed `.go` files → no output, `GOFMT_EXIT=0`.
- **Manifest:** `sha256sum -c .hermes/evidence/p10/r16q2-superseding/SHA256SUMS` → all 17 entries `OK`, `MANIFEST_EXIT=0`.
- **Flake probe (extra):** endpoint-release tests at `-race -count=3`, run 3 times → all `ok`.
- **New repair tests run individually under `-race -v`:** all 8 (incl. 3 subtests) `PASS`.

## Findings

- **MINOR** — `internal/agent/control/session.go:612-628, 630-651` with `session.go:503-505`: when deletion-only convergence fails, the raw error propagates out of `handleCommandOnSession`, and the session read loop treats *any* frame error as fatal (`stopSession`). A persistently failing cleanup therefore yields one teardown+reconnect per controller redelivery, with no backoff on this path (`reconnectControl`, `internal/agent/app.go:476-487`, backs off only failed connects). **Not a correctness defect:** `RecoveredDeletionPending` is durable (`journal.go:132-134`), the pending deletion fence stays installed, C is never NACKed prematurely, and the retry is proven by `TestLegacyRecoveredDeleteRedeliveryConvergesWithoutReplayingCommand`. Deliberate design trade-off, flagged for operational awareness.
- **NOTE** — `internal/agent/localstate/journal.go:377-383`: the journal-only duplicate branch returns `Duplicate=true` checking only Kind and MessageID, unlike the inbox-present branch (`journal.go:327-375`) which also enforces payload hash and bytes. Unreachable with conflicting bytes: inbox and journal rows are created atomically together (`journal.go:385-397`) and destroyed atomically together with the receipt key in `AcceptReceipt` (`journal.go:806-816`, the only inbox delete in the codebase), and the receipt gate runs first (`journal.go:322`). Where `messageID != operationID` it fails closed on the MessageID mismatch. Defense-in-depth asymmetry only.
- **NOTE** — `internal/agent/localstate/journal.go:363-366, 397-401`: `ErrForwardDeleteConflict` from `putForwardDeleteIntentTx` is deliberately swallowed in both paths. Not fail-open on durable state — the conflicting put writes nothing — and the authoritative conflict is surfaced later by the tombstone identity check (`internal/agent/reconcile/desired.go:266-270`) and the merge fence check (`internal/agent/localstate/applied.go:328-332`). A conflicting classification cannot arise without a SHA-256 collision, since journal classification is derived from the same hash-gated payload.
- **NOTE** — `internal/agent/localstate/journal.go:360, 526`: recovered-NACKED detection matches the raw string literal `"recovered APPLYING operation after restart"` duplicated at two sites instead of a shared constant. Drift would stop arming the flag for already-NACKED legacy rows; the deletion is still retried via the durable fence, so nothing is lost, but convergence would be skipped for that row.
- **NOTE** — `internal/agent/localstate/journal.go:557`: `CompleteOperation` does not clear `RecoveredDeletionPending`, so a fully applied command can carry a stale-true flag. Benign: reaching APPLIED means the full snapshot including ABSENT cleanups finished, and the APPLIED duplicate branch (`session.go:604-611`) deliberately ignores the flag.
- **NOTE** — `test/e2e/harness/harness.go:289-303`: `waitForEndpointRelease` is correctly deadline-bounded (deadline checked before each `time.Sleep`, `harness.go:298-301`), returns the listener only on success and `nil` on the timeout path, so it cannot leak internally. It narrows but does not eliminate the window where a parallel process grabs the port first — in that case the test fails loudly rather than false-passing, which is the intended strictness versus the old silently-tolerant `AssertForwardGone`.

**Positive verification of the mandated scope** (no findings): bbolt atomicity holds — every transition is one `db.Update`, and no bbolt tx is held across the `OnRecoveredDeletion` callback, so there is no store/dp.mu/probeAdmissionMu lock cycle (no store method acquires `probeAdmissionMu`; `onForwardRunError` releases it before cleanup callbacks, `app.go:869-887`). `convergeRecoveredDeletions` filters `Presence==ABSENT` (`app.go:712-713`) and gates on `report.Status == ApplyStatusFull` (`app.go:727-728`); the PRESENT path refuses on pending/tombstone (`desired.go:293-299`) and `CommitDesired` rejects `ApplyApplied` on a tombstoned forward (`applied.go:474-479`), so tombstoned forwards cannot resurrect; the received-desired merge is union-preserving (`applied.go:307-311`), so the ABSENT-only subset does not destroy PRESENT retry intent. Payload integrity: exact bytes persisted (`journal.go:356, 390`), `PayloadPresent` preserves the zero-byte distinction, a conflicting hash-matching redelivery fails closed (`journal.go:352-354`), and the durable payload is written only when `!j.PayloadPresent` (`journal.go:355`) so no different payload can ever replace one. `recordResultAndQueue` tolerates an existing outbox row (`journal.go:694-696`), so the NACKED re-queue is idempotent with no duplicate delivery.

## VERDICT: PASS

Zero BLOCKER findings against the unchanged candidate C3 tree.
