# P09 per-Story TDD RED evidence (forward data plane)

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent or bug-present reasons.

## Story 3 — TCP forwarding and half-close

RED command: `GOWORK=off go test ./internal/forward/... -count=1`

RED reason: the forward packages had no production files (feature absent):

```
github.com/gxbrave/AntiNAT/internal/forward: no non-test Go files
github.com/gxbrave/AntiNAT/internal/forward/tcp: no non-test Go files
internal/forward/backend_test.go:22:16: undefined: NewBackend
FAIL    github.com/gxbrave/AntiNAT/internal/forward [build failed]
FAIL    github.com/gxbrave/AntiNAT/internal/forward/tcp [build failed]
```

GREEN: `forward.Backend` parses and validates an IPv4 literal:port target
(hostnames and IPv6 rejected — v1 Forwards are IPv4-only). `tcp.Forward`
runs an accept loop that dials the backend per session and proxies both
directions with correct half-close semantics: EOF on one direction
propagates `CloseWrite` to the peer, and both sockets are fully closed only
when both directions finish — a client can keep writing after observing
read-EOF and a server reply survives the client's CloseWrite (v0.8 §4.2).
A failed backend dial closes the client connection without stopping the
accept loop (verified by bringing the target up on the same port and
serving a second client end-to-end). Transient accept errors (EMFILE)
retry with a doubling bounded backoff, verified by timestamps, not a
busy loop. Run exits cleanly when the listener is closed or ctx cancels.

Test-double fixes during GREEN (test bugs, not production bugs): the bulk
echo expectation originally assumed one "T:" prefix for the whole payload
but the echo server prefixes every 32 KiB chunk, so the expectation was
rewritten to mirror the chunking; `flakyListener` initially held its mutex
across the blocking real `Accept`, deadlocking `failureTimes()` under
`-race` (and once without), fixed by releasing the lock before delegating.

## Story 4 — Backend hot update

RED command: `GOWORK=off go test ./internal/forward/... -count=1`

RED reason: `Backend.Update` did not exist (feature absent):

```
internal/forward/backend_hotupdate_test.go:18:20: backend.Update undefined (type *Backend has no field or method Update)
internal/forward/tcp/hotupdate_test.go:58:20: backend.Update undefined (type *forward.Backend has no field or method Update)
FAIL
```

GREEN: `Backend.Update` validates the new IPv4 literal:port and swaps the
atomic snapshot; an invalid update leaves the snapshot untouched. The proxy
already resolved the backend once per accepted session, so after a hot
update the established connection keeps talking to its original target
while new connections use the new snapshot (verified end-to-end with two
distinct echo targets A/B: old session still echoes A after Update to B,
new session echoes B) — NEW_SESSIONS_ONLY semantics (v0.8 §4.5).

## Story 5 — Budgets and delete hook

RED command: `GOWORK=off go test ./internal/forward/... -count=1`

RED reason: budget symbols, `Options.Budget/OnReject`, `Close`, and `Stats`
did not exist (feature absent):

```
internal/forward/budget_test.go:13:17: undefined: NewBudget
internal/forward/budget_test.go:13:27: undefined: Limits
internal/forward/budget_test.go:21:21: undefined: ErrBudgetExceeded
internal/forward/tcp/budget_stop_test.go:33:8: opts.Budget undefined (type *tcp.Options has no field or method Budget)
internal/forward/tcp/budget_stop_test.go:144:20: proxy.Stats undefined (type *tcp.Forward has no field or method Stats)
internal/forward/tcp/budget_stop_test.go:148:18: proxy.Close undefined (type *tcp.Forward has no field or method Close)
FAIL
```

GREEN: `forward.Budget` bounds connections, FDs, and the pessimistic 64 KiB
per-connection fallback-buffer reservation (v0.8 §4.4); exhaustion returns
the explicit `*BudgetExceededError` carrying the axis kind, limit, and
current usage, and never partially charges. Zero limits mean unlimited;
negative limits are rejected. The proxy reserves the budget in the accept
loop, rejects the excess connection with the explicit reason (surfaced via
`OnReject` and the `Rejected` counter), and frees capacity on session end.
`Close` — the delete hook (M1 online DELETE) — closes the listener, waits
for the accept loop to exit, closes every tracked session, and waits for
them; it is idempotent and safe before Run ever starts. A `runMu` serializes
Close against the accept-loop lifetime so `wg.Add` can never race `wg.Wait`.

Test-expectation fix during GREEN: the final stats assertion originally
expected accepted=3, but the budget-rejected connection is never counted as
accepted — corrected to accepted=2 (first + third), rejected=1.

## Story 6 — Data-path evidence
(pending)
