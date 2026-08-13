# P08 per-Story TDD RED evidence

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent or bug-present reasons.

## Story 1 — enrollment challenge/request/result

RED command: `go test ./internal/security/ ./internal/controller/store/ ./internal/controller/agenthub/ ./internal/agent/control/ -count=1`

RED reason: packages/symbols absent (feature absent):

```
internal/security: no non-test Go files
internal/security/challenge_test.go:49: undefined: security.NewChallengeManager
internal/controller/store/enrollment_test.go:47: s.CreateEnrollmentToken undefined
internal/controller/agenthub/enroll_test.go:20: could not import .../agenthub
internal/agent/control/enroll_test.go:19: could not import .../control
```

GREEN: ChallengeManager issues signed EnrollChallenges with a bounded TTL
replay cache (unknown/expired/replayed fail closed; cross-node identity is
enforced at token binding since the EnrollRequest carries no node id);
store.ConsumeEnrollmentToken performs the frozen single-transaction
consume/bind/result with idempotent response-loss replay and uniform
different-key rejection + audit; agenthub exposes the enrollment HTTP
handlers (plaintext-public refused by default); the agent enroll client
verifies the challenge/result against the PINNED controller key and persists
the pin.

## Story 2 — secret-safe bootstrap

RED command: `go test ./internal/security/ ./internal/agent/control/ -count=1`

RED reason: undefined key symbols (feature absent); after GREEN the tests
assert 0600 mode, atomic reload stability, concurrent load-or-create
convergence, corrupt-file fail-closed without key leakage, and token/private
key absence from errors, logs, and the store (hash-only).

One real RED caught mid-story: `TestNodeKeyConcurrentLoadOrCreate` FAILED
after the first GREEN because each goroutine returned its own generated key
instead of the on-disk key (file race). Fixed by making the file
authoritative: every caller reloads and returns the final file content.

## Story 3 — signed session handshake (bounded WebSocket)

RED command: `go test ./internal/security/ ./internal/controller/agenthub/ ./internal/agent/control/ -count=1`

RED reason: undefined session symbols + deadlock bug caught by the E2E tests:

```
session_test.go:47: ParseSessionHello: security: session hello too large
  (fixed: pre-filter constants miscounted; corrected to 7 fields)
internal/agent/control/session_test.go: undefined: control.NewClient
```

A real RED caught mid-story in `TestSessionFrameVerificationFailsClosed`:
the controller never processed the bad frame — `Hub.register` held
`sessionsMu` while calling `old.close()` which re-entered `unregister`
(deadlock). Fixed by closing the old session outside the map lock.

GREEN: the mutual-challenge transcript (hello presents the agent key; the
controller cross-checks the credential hash and the signature; welcome is
verified against the pinned controller key; final echoes the server nonce),
bounded WS read limit, and per-frame direction/domain/epoch/session/sequence
verification with fail-closed session termination.

## Story 4 — bidirectional epoch fencing

RED command: `go test ./internal/controller/agenthub/ -run TestEpoch -count=1`

RED reason: undefined session/epoch symbols (feature absent).

GREEN: the hub CASes the node epoch per handshake (CASNodeConnectionEpoch),
rejects an agent claiming an epoch the controller never issued (rollback/
split-brain fails closed), keeps one active session per node, and rejects the
old socket's validly-signed frames after a new epoch. The agent persists the
granted epoch/session BEFORE sending SessionFinal/socket activation.

## Story 5 — reconnect and semantic resend

RED command: `go test ./internal/agent/control/ -run TestReconnect -count=1`

RED reason: controller outbox rows stuck at PENDING after reconnect — the
result arrived before the pump re-claimed the requeued row and
`matchOutboxRow` only looked at CLAIMED/SENT/SEMANTIC_ACKED, so the result
was rejected as unmatched (`CONTROL_FRAME_REJECTED`). Fixed by including
PENDING rows in the correlation and legally advancing
PENDING->CLAIMED->SENT->SEMANTIC_ACKED when the result beats the pump; the
agent-side receipt handler and pump were made tolerant of the same race.

GREEN: controller outbox FSM store methods (claim/sent/semantic-ack/
receipt/requeue, session-bound single-step), control inbox message_id dedup,
agent outbox pump with deterministic message ids (same operation/message id
re-enveloped on reconnect), receipts both directions, and
`TestReconnectResendsResultWithoutDuplicateSideEffect` proving exactly one
side effect per operation across a hard disconnect.

## Story 6 — transport boundaries

RED command: `go test ./internal/agent/control/ -run TestDial ./internal/controller/agenthub/ -run TestOversize -count=1`

RED reason: undefined DialEndpoint / no read-limit enforcement (feature
absent).

GREEN: family-aware dialer (A-only, AAAA-only, dual with IPv4-first
fallback; per-attempt deadline; no-address/malformed fail closed), oversize
WS message closes the session (read limit = max envelope), oversize enroll
bodies rejected, garbage handshake message fails closed, and plaintext
public enrollment refused by default with loopback plaintext still allowed.

## FIX1 — repair cycle 1 (P08-QUALITY F1 + F2)

F1: the controller requeued SEMANTIC_ACKED outbox rows on reconnect,
re-delivering a command the agent had already durably receipted; the agent
journal failed closed with ErrAlreadyReceipted, the session died, and the
row leaked in SENT with reconnect churn (liveness + unbounded retention).

RED command (F1-a): `go test ./internal/controller/store/ -run TestControlOutboxRequeueSkipsSemanticAcked -count=1`

RED reason: `requeued = 2, want 1` — RequeueControlOutboxForSession reset
the SEMANTIC_ACKED row to PENDING.

RED command (F1-c): `go test ./internal/agent/control/ -run TestReconnectAfterDurableAgentReceiptKeepsSessionAlive -count=1`

RED reason: `op-1 state after reconnect = "PENDING", want SEMANTIC_ACKED` —
the tombstoned-agent corner row was requeued (and re-delivered, killing the
session).

RED command (F1-b): `go test ./internal/agent/control/ -run TestReconnectResultResendHealsSemanticAckedRow -count=1`
after the (a) requeue fix landed but before the (b) handler fix.

RED reason: `op-1 row not GC'd by the result-resend heal: state=SEMANTIC_ACKED`
— with the row no longer requeued, the result resend hit handleAgentResult
with no SEMANTIC_ACKED case; the strict SENT->SEMANTIC_ACKED ack failed as
stale-session and the session died, so the row never healed.

RED command (rebind method): `go vet ./internal/controller/store/`

RED reason: `s.RebindControlOutboxSession undefined` (new store method
absent).

GREEN (F1):
- `RequeueControlOutboxForSession` requeues only CLAIMED/SENT; SEMANTIC_ACKED
  rows are never re-delivered (late GC is P14 receipt-TTL sweeper scope).
- `handleAgentResult` gains a SEMANTIC_ACKED case: the deduped result resend
  re-binds the row to the new session (new `RebindControlOutboxSession`
  store method, fail-closed for non-SEMANTIC_ACKED), skips the FSM advance,
  and re-writes the idempotent C2A receipt so the agent GCs its own row and
  the follow-up A2C receipt completes the controller GC — the receipt-window
  row heals end to end. SENT rows keep the pre-FIX1 fall-through (the strict
  ack is their legal advance).
- `TestReconnectResendsResultWithoutDuplicateSideEffect` updated to the new
  contract: rows are terminal when GONE or SEMANTIC_ACKED, and any retained
  row must coexist with an ONLINE session (the pre-FIX1 code killed the
  session and leaked the row in SENT). The second command is enqueued only
  after the first apply so the hard disconnect is timed after processing,
  never inside it.

F2: `protectDPAPI`/`unprotectDPAPI` returned `unsafe.Slice` into the DPAPI
output buffer after the deferred `windows.LocalFree` had freed it
(use-after-free on every Windows key-file load/save). Fixed by copying into
a Go-owned buffer before the deferred free. Windows-tagged round-trip test
(`keyfile_windows_test.go`) compiles under GOOS=windows (vet + test -c);
runtime requires a Windows host (cross-build evidence this milestone).
