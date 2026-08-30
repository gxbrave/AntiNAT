# Formal Review 3/4 — NETWORK/PROTOCOL

- Candidate: C3 = commit 256c91046a00c6c18a43facf1f6ff73b576f3b23 / tree 576a3d683ee78cbacba427a6055a2a925a2d8725
- Reviewed at: metadata tip 676c6b60a8431ead4a3820a5830843526ecffdab (tree c34f55d1c62d7c9686175739ecc0d1e6621c9986)
- Reviewer: independent agent, read-only
- First attempt: FAIL at identity gate (same mandate contradiction). Resumed under corrected protocol; substantive review completed.

## 1. Verified identity line (reviewed state)

Corrected four-part gate — **all four checks pass, verified independently**:

```
(1) HEAD                      = 676c6b60a8431ead4a3820a5830843526ecffdab   == expected  ✓
(2) 256c91046a00...^{tree}    = 576a3d683ee78cbacba427a6055a2a925a2d8725   == expected  ✓
(3) git status --porcelain    = empty (0 lines)                                         ✓
(4) git diff --name-only 256c9104..HEAD
      .hermes/handoffs/P10-r16q2-superseding.json
      .hermes/handoffs/P10.json
    paths outside .hermes/handoffs/ : 0   →  metadata-only delta confirmed, not trusted
                                            from the message                            ✓
```

Branch `handoff/P10-r16q2-resume` = `676c6b60`; `256c9104` is its parent. Working tree is byte-identical to C3 for every path outside `.hermes/handoffs/`.

## 2. Tests actually run (real output, not fabricated)

| Command | Result |
|---|---|
| `GOWORK=off go test ./test/e2e -run TestLinuxDirectV4WalkingSkeleton -count=3 -v` | `ok github.com/gxbrave/AntiNAT/test/e2e 3.909s`, `E2E_EXIT=0`. **3/3 `--- PASS: TestLinuxDirectV4WalkingSkeleton (1.30s)`, 0 `SKIP`.** No `t.Skip`/`Skipf` exists in the test file — the capability requirement is a `t.Fatalf`, so a missing capability fails honestly rather than skipping. |
| `GOWORK=off go test ./internal/agent/control -count=1 -race` | `ok github.com/gxbrave/AntiNAT/internal/agent/control 4.994s`, `CONTROL_EXIT=0`. Race detector clean. |

## 3. Findings

**Scope 1 — control-plane duplicate phases** (`internal/agent/control/session.go:579-704`): all five phases protocol-correct.
- `APPLIED` :602-611 fail-closed — errors if no queued result exists (:609) rather than re-invoking the side effect. Sound: `RequeueOutboxForSession` at :383 resets `SENT`→`PENDING` on every handshake and the pump polls at 50ms (:31, :881-895); receipted rows are *deleted*, not marked (`journal.go:804`), so requeue cannot resurrect an acked result.
- `NACKED` :612-629 requeues the NACK (:629); with a recovered deletion it runs ABSENT-only convergence then `CompleteRecoveredDeletion` first, and an error defers the NACK — the designed durable retry.
- `APPLYING` :630-654 **never re-invokes `OnCommand`** — proven by `command_fence_test.go` asserting `normalApply.Load()==0` for a legacy APPLYING row.
- `RECEIVED`/:655-658 and `INTENT_PERSISTED`/:659-661 resume the pipeline correctly (no side effect yet); `default` :662-663 fails closed on unknown phase; :666-681 restricts fall-through to those two.
- Sequence numbers / signed frames untouched by the delta: the session.go diff contains zero `Seq`/`Sign`/`hmac`/`frame` lines; enforcement at :544-551 and identity reset at :380-381 are unmodified.
- Frame handling is strictly serial per session (`frameLoop` :494-508 calls the handler synchronously), and the controller sends each command exactly once per session (`agenthub/session.go:915,928,939`), so an `APPLYING` duplicate is genuinely a post-reconnect crash-recovery path, never a mid-apply race.

**Scope 2 — payload identity** (`internal/agent/localstate/journal.go:242-406`): no swap / replay / cross-kind path found.
- sha256 over the exact wire payload recomputed every receive (:243-244); inbox mismatch on type **or** hash → `ErrMessageConflict` (:332-334).
- Cross-kind blocked twice: inbox `MessageType` (:332) and journal `Kind`+`MessageID` (:345-347, :380-382). Conflicting durable bytes rejected (:349-351); conflicting classification rejected (:352-354).
- `PayloadPresent` (:129-131, set from messageType :246) correctly separates a zero-byte payload from an absent one, and is persisted *before* the classification ok-check (:248-252) so a malformed payload is still journalled.
- `classifyForwardDeletions` (:284-306) handles exactly `desired` and `forward_delete`; `ok=false` → links discarded (:253-255) while the transaction still journals (:257-261) — fails closed on classification, still journals. Matches the mandate.
- Payload backfill is gated on `!j.PayloadPresent` (:355-362) and can only run after the hash already matched, so the C1 payload-less recovery hole is closed without opening a swap path.

**Scope 3 — datalane deletion** (`internal/agent/reconcile/desired.go:255-393`, `forward_delete.go`): tombstone-before-stop upheld; no false `COMPLETED`.
- Tombstones commit in the same atomic `CommitDesired` (:340) *before* any stop hook runs (:348-373).
- `OutcomeDeleted` is downgraded to `OutcomeDeleteFailed` on fence read error (:356-359), stop failure (:364-367), or completion failure (:369-372) — the agent cannot report success while the listener is still owned. `reconciler.go:65-86` emits `deleted=true` only for `OutcomeDeleted`, and the controller marks `COMPLETED` solely from that ack (`minapi.go:753-755`).
- `CompleteForwardDeleteIntent` requires the matching tombstone (`forward_delete.go:229-231` → `ErrForwardDeleteNotCommitted`).
- `putForwardDeleteIntentTx` never recreates a pending row once a tombstone exists (:102-115), so `RecoverApplyingOperations`' fence re-assert (`journal.go:515-524`) cannot resurrect work.
- Rollup :375-391 (`Full`/`Partial`/`Failed`) is correct, and `convergeRecoveredDeletions` (`app.go`, new) filters to the `PresenceAbsent` subset only and demands `ApplyStatusFull` else errors.

**Scope 4 — endpoint-release oracle** (`test/e2e/harness/`): a genuine OS-boundary claim.
- `waitForEndpointRelease` (:289-303) uses plain `net.Listen("tcp4", endpoint)` with no `SO_REUSEPORT`, so success proves nothing is bound on that exact tuple. The endpoint is the published one (`walking_skeleton_test.go:130`, asserted `== harness.GlobalLiteral` at :127).
- Both required cases covered: held-forever (`endpoint_release_test.go:11-21` — active listener must **not** report released) and closed-then-bindable (:23-37). The old permissive `AssertForwardGone` (which tolerated "an unrelated listener accepted the connection") was removed, not weakened.
- Reserving the tuple across restart (`walking_skeleton_test.go:252-264`) cannot mask a resurrection: the post-restart assertion is durable state (`GetAppliedState`, :262-264), independent of network bindability, and `OutcomeTombstonedRejected` (`desired.go:295-301`) fences any PRESENT re-apply.

**Scope 6 — truthfulness**: clean. `harness.go:37-39` explicitly labels `GlobalLiteral` as the *loopback-aliased* global-class source ("the orchestrator host has no real global IPv4"); `harness.go:41-44` says the alias makes it "bindable and locally reachable". The test itself enforces `WanReachabilityState == "NOT_TESTED"` after restart (`walking_skeleton_test.go:202-206`) rather than fabricating provider evidence. `protocol/domain.go:314-327` enforces that `PUBLISHED_UNVERIFIED` can never claim `OPEN_FROM_VANTAGE`. The handoff (`P10-r16q2-superseding.json:72, 279-282`) states the M1 fixture is non-independent and claims no public-WAN evidence. No file in the candidate describes loopback evidence as independent public-WAN reachability. Evidence is honest: `results.tsv` records `13-govulncheck` and `14-netns-integration` at exit 125, matching `known_limits`.

**Findings list:**

1. **MINOR** — `internal/agent/control/session.go:613-628,635-650` + `internal/agent/app.go:463-491`. A *deterministically* failing recovered-deletion convergence returns an error from the frame handler → `stopSession` → reconnect, and the controller resends on every new session (`agenthub/session.go:915`). `reconnectControl` applies its 250 ms backoff only when `Connect` returns an error (`app.go:477-481`), not on a teardown-driven boundary, so this path can loop unbounded at handshake latency and never terminal-NACK C. This is the correct trade-off (NACKing without converged cleanup would report failure while the ABSENT side effect is still owed — the C1 defect), and it requires an adversarial permanent failure, but there is no backoff or attempt bound on it.
2. **NOTE** — `internal/agent/control/session.go:602-611`. The `APPLIED` duplicate branch does not itself nudge the outbox pump; it relies on the 50 ms ticker plus handshake requeue. No liveness defect found (see Scope 1 analysis).
3. **NOTE** — `internal/agent/control/session.go:387-400`. `Connect` does not drain the previous session's workers (`waitWorkers` at :257 is unreferenced on the connect path), so a prior session's handler can briefly overlap a new one. Pre-existing and untouched by the delta; harmless here because the old handler's ctx is cancelled (`:280-282`), bbolt serialises journal writes, and recovered-deletion convergence is idempotent and tombstone-fenced.
4. **NOTE** — `test/e2e/walking_skeleton_test.go:249-264`. The post-restart no-resurrection assertion is durable-state only; the former post-restart echo probe was deleted. No coverage was actually lost — the durable check is stronger than the echo probe ever was, and the tuple reservation is what prevents third-party impersonation — but a purely network-layer resurrection *attempt* inside the reserved window would be blocked by the reservation and go unobserved rather than failing the test.
5. **NOTE** — `test/e2e/harness/harness.go:289-303`. The oracle's validity depends on Go's default `ListenConfig` (SO_REUSEADDR only, never SO_REUSEPORT). Correct on Linux, but the absence of SO_REUSEPORT is implicit; an explicit assertion or comment would pin it against future refactoring.
6. **NOTE** — `internal/agent/localstate/journal.go:246,332`. For non-deletion kinds `PayloadPresent` is false and no bytes are persisted, so their anti-swap guarantee rests solely on the inbox sha256 comparison. Sufficient (sha256 over the exact wire payload), but it means those payloads are not byte-comparable on redelivery.

## 4. VERDICT

**PASS**

Zero BLOCKER findings against the unchanged candidate C3 tree.
