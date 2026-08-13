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
(pending)

## Story 5 — Budgets and delete hook
(pending)

## Story 6 — Data-path evidence
(pending)
