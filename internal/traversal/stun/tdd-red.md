# P11 per-Story TDD RED evidence

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent or bug-present reasons.

## Story 1 — STUN RFC 8489 message codec

RED command: `GOWORK=off go test ./internal/traversal/stun/ -count=1`

RED reason: the stun package had no codec symbols (feature absent):

```
internal/traversal/stun/message_test.go:50:14: undefined: hexDecode
internal/traversal/stun/message_test.go:59:14: undefined: ParseMessage
internal/traversal/stun/message_test.go:63:17: undefined: MessageTypeBindingRequest
internal/traversal/stun/message_test.go:69:26: undefined: AttrSoftware
internal/traversal/stun/message_test.go:92:14: undefined: ParseMessage
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun [build failed]
```

GREEN: bounded codec with strict bounds — header/attribute lengths, length%4
gate, FINGERPRINT-last enforcement, MESSAGE-INTEGRITY boundary over the
original wire bytes (exotic 0x20 padding preserved), XOR-MAPPED-ADDRESS v4/v6,
ERROR-CODE/300, ALTERNATE-SERVER, UNKNOWN-ATTRIBUTES, CSPRNG transaction IDs.

Golden corpus: the RFC 5769 sample request / IPv4 response / IPv6 response
were independently re-derived and verified with a Python reference
implementation (`hmac`/`hashlib`/`zlib`), byte-matching the published
MESSAGE-INTEGRITY and FINGERPRINT values, before being pinned in the Go
tests. A zero-padding marshal vector was generated the same way.

## Story 2 — Transaction-safe UDP client

RED command: `GOWORK=off go test ./internal/traversal/stun/ -run TestUDP -count=1`

RED reason: the UDP client symbols were absent (feature absent):

```
internal/traversal/stun/udp_test.go:119:12: undefined: NewUDPClient
internal/traversal/stun/udp_test.go:119:31: undefined: UDPClientOptions
internal/traversal/stun/udp_test.go:262:21: undefined: ErrTimeout
internal/traversal/stun/udp_test.go:309:32: undefined: ErrAlternateLoop
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun [build failed]
```

GREEN: caller-owned socket, one demux reader routing datagrams to waiters by
transaction ID + exact server tuple + class + method, so concurrent exchanges
cannot steal responses (v0.8 §4.3). RFC 8489 §6.2.1 retransmission (RTO
doubling, Rc cap, Rm×RTO final wait, ctx-bound). RFC 8489 §10 alternate-server
300 handling (fresh transaction ID, visited-set + MaxAlternates loop bound).

## Story 3 — TCP framing and persistent client

RED command: `GOWORK=off go test ./internal/traversal/stun/ -run TestTCP -count=1`

RED reason: TCP client symbols absent (feature absent):

```
internal/traversal/stun/tcp_test.go:133:17: undefined: DialTCP
internal/traversal/stun/tcp_test.go:133:69: undefined: TCPClientOptions
internal/traversal/stun/tcp_test.go:219:21: undefined: ErrDisconnected
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun [build failed]
```

GREEN: STUN-only TCP framing via the header length field (RFC 8489 §6.2.2),
tolerating partial header/body reads, rejecting oversize and
non-multiple-of-4 declarations before allocation, mapping EOF/reset to
ErrDisconnected. One request per transaction (no STUN-layer retransmit), Ti
default 39.5 s, pipelined concurrent exchanges demuxed by transaction ID,
`Disconnected()` closed on transport loss (v0.8 §3.5 mapping invalidation),
protocol errors propagate to waiters, user Close distinct from disconnect.

## Story 4 — Shared-port sockets

RED command: `GOWORK=off go test ./internal/traversal/stun/ -run TestSharedPort -count=1`

RED reason: shared-port symbols absent (feature absent):

```
internal/traversal/stun/sharedport_test.go:56:20: undefined: stunReuseControl
internal/traversal/stun/sharedport_test.go:83:6: undefined: SharedPortSupported
internal/traversal/stun/sharedport_test.go:89:14: undefined: NewSharedPortRegistry
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun [build failed]
```

GREEN: SharedPortRegistry mirrors the P09 PortRegistry ownership discipline
(owner, generation, atomic acquire inside the registry critical section,
actual-port resolution, wildcard/specific overlap rejection, stale releases
can never close a new owner). Linux: reuse-enabled listener plus connected
sockets sharing one tuple (P02 tcp-shared-port-linux.json
SUPPORTED_WITH_LIMITS; every participant pre-binds SO_REUSEADDR+SO_REUSEPORT).
Platform adapters: linux gate on; windows/other gate off (cross-build only);
OS bind stays the final ownership authority.

Socket-behavior probe (before coding): a standalone Linux experiment proved a
plain listener (P09 style) cannot host reuse-enabled connected sockets
(EADDRINUSE), while a reuse listener + two reuse connects to distinct remotes
shares one tuple deterministically — this drove the adapter design.

## Story 5 — Honest concurrent mapping evidence

RED command: `GOWORK=off go test ./internal/traversal/stun/ -run TestObserveMapping -count=1`

RED reason: evidence symbols absent (feature absent):

```
internal/traversal/stun/evidence_test.go:53:22: undefined: ObserveMapping
internal/traversal/stun/evidence_test.go:53:59: undefined: ObserveMappingOptions
internal/traversal/stun/evidence_test.go:62:28: undefined: VerdictEIMObservedConcurrent
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun [build failed]
```

GREEN: EIM_OBSERVED_CONCURRENT recorded only when the platform shared-port
gate passes AND the first connection stays ESTABLISHED through the second
observation (zero-byte read probe). Gate-off or interrupted runs yield
PORT_REUSE_OBSERVED (same mapped port across destinations) or
MAPPED_UNVERIFIED, flagged Concurrent=false / FirstConnStayedEstablished=false
— EIM is never claimed from sequential or interrupted observations.

## Story 6 — Endpoint health and fuzz

RED command: `GOWORK=off go test ./internal/traversal/stun/ -run TestHealth -count=1`

RED reason: health symbols absent (feature absent):

```
internal/traversal/stun/health_test.go:19:12: undefined: NewEndpointHealth
internal/traversal/stun/health_test.go:19:30: undefined: HealthOptions
internal/traversal/stun/health_test.go:20:51: undefined: TransportUDP
internal/traversal/stun/health_test.go:81:50: undefined: ErrCooldown
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun [build failed]
```

GREEN: per-transport (transport, host, port) keying of DNS/IP, cooldown, RTT
and success-rate state; literal IPs skip DNS; hostname resolution caches once
per endpoint; DNS failure counts and cools down; cooldown engages after the
failure threshold with exponential backoff capped at CooldownMax and clears
on success; Ready fails fast with ErrCooldown.

Fuzz: single FuzzMessage target exercises ParseMessage and readFrame on the
same corpus; `-fuzz=Fuzz -fuzztime=30s` ran 6.2M execs with zero panics.

## P11-FIX1 — repair cycle 1 (P11-NETWORK findings N1–N3 + QUALITY #1)

### FIX1-N1: alternate-server address-class policy (udp.go)

RED command: `GOWORK=off go test ./internal/traversal/stun -run TestUDPExchangeAlternate -count=1 -v`

RED reason: the new policy tests failed because the policy was absent — the
client followed 300 Try Alternate unconditionally (default-enabled, no
global-unicast validation):

```
--- FAIL: TestUDPExchangeAlternatesDisabledByDefault
    udp_test.go:393: reply error code = 0 (stun: malformed message structure), want the 300 returned un-followed
--- FAIL: TestUDPExchangeAlternatesExplicitlyDisabled
    udp_test.go:393: reply error code = 0 (stun: malformed message structure), want the 300 returned un-followed
--- FAIL: TestUDPExchangeAlternateRejectsNonGlobalAddress (loopback + rfc1918-private subtests)
FAIL    github.com/gxbrave/AntiNAT/internal/traversal/stun
```

GREEN: `MaxAlternates` now defaults to 0 (redirection disabled by default,
frozen design reference §6) with `DisableAlternates` as the explicit kill
switch; when enabled, every alternate must pass `defaultAlternateAllowed`
(global unicast per RFC 8489 §10 — implemented as IsGlobalUnicast AND NOT
IsPrivate AND NOT RFC 6598 CGNAT, because Go's `netip.Addr.IsGlobalUnicast`
reports true for RFC 1918 private space, which the finding's required
private-alternate regression test must reject). Rejected alternates return
ErrAlternateLoop. The two pre-existing redirection tests (300-follow,
loop-bounded) were updated per the finding: they opt in via MaxAlternates
and the unexported `alternateAllowed` test seam (loopback servers are not
global unicast). Regression coverage: loopback, RFC 1918, and RFC 6598
CGNAT alternates rejected with zero datagrams sent to the alternate;
disabled-by-default and explicit-kill-switch both return the 300 un-followed.

### FIX1-N2: Dial-vs-Release race (sharedport.go)

RED command: `GOWORK=off go test ./internal/traversal/stun -run TestSharedPortDialRacingReleaseClosesSocket -count=1 -v`

RED reason: a dial completed after Release handed its socket to the released
lease (no released check), leaving it unowned:

```
sharedport_test.go:347: Dial = <nil>, want ErrStaleLease (socket must not outlive its lease)
--- FAIL: TestSharedPortDialRacingReleaseClosesSocket
```

GREEN: `released` flag set under l.mu before the conn list is drained; Dial
checks it before dialing and again after the dial completes, closing the
socket immediately and returning `traversal.ErrStaleLease` when Release won
the race. The `beforeAppend` seam makes the race deterministic (the dial is
paused exactly at the hand-over point); the test also asserts the server
observes EOF (socket actually closed) and that the tuple is re-acquirable.

### FIX1-N3: IPv4-mapped source matching (udp.go)

RED command: `GOWORK=off go test ./internal/traversal/stun -run TestUDPExchangeIPv4MappedSourceOnDualStackSocket -count=1 -v`

RED reason: on a dual-stack caller socket the response source arrives as
::ffff:a.b.c.d and never equals the plain-IPv4 server tuple, so the exchange
timed out:

```
udp_test.go:489: Exchange over dual-stack socket: stun: UDP transaction timed out
--- FAIL: TestUDPExchangeIPv4MappedSourceOnDualStackSocket
```

GREEN: `readerLoop` unmaps the source (`source.Addr().Unmap()`) before the
waiter tuple comparison (same idiom as P09 FIX1 / health.resolveIP).

### FIX1-QUALITY#1: ReuseControl documented default (evidence.go)

RED command: `GOWORK=off go test ./internal/traversal/stun -run TestObserveMappingSameLocalPortDefaultReuseControl -count=1 -v`

RED reason: the doc promised `ReuseControl` defaults to
`traversal.StunSharedPortControl`, but the code used the field as-is; the
nil-control same-tuple rebind collided with the first socket's TIME_WAIT and
the observation silently degraded:

```
evidence_test.go:126: verdict = MAPPED_UNVERIFIED, want PORT_REUSE_OBSERVED
--- FAIL: TestObserveMappingSameLocalPortDefaultReuseControl
```

GREEN: `ObserveMapping` defaults a nil `ReuseControl` to
`traversal.StunSharedPortControl` (mirroring the `PlatformGate` default),
so gate-off sequential same-local-port observation works as documented.

## Required verification (final)

- `go test ./internal/traversal/stun -race -count=10` — PASS (exit 0)
- `go test ./internal/traversal/stun -fuzz=Fuzz -fuzztime=30s` — PASS (6.2M execs, no panic)
- `GOOS=windows GOARCH=amd64 go test -c ./internal/traversal/stun` — PASS (cross-build)
- `go test ./... -count=1` (sandbox env UID/GID 12001) — PASS
- `go test -race ./... -count=1` (sandbox env) — PASS
- `go vet ./...` — PASS
- `gofmt -l internal/` — clean; `git diff --check` — clean
- `go test ./test/contracts -run TestContractManifest` — PASS (frozen gate)
- `make build` + `make clean` — PASS
