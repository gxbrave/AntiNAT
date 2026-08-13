# P09 per-Story TDD RED evidence

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent or bug-present reasons.

## Story 1 — Route and IPv4 capability

RED command: `GOWORK=off go test ./internal/traversal/ -count=1`

RED reason: the traversal package had no route/source symbols (feature
absent):

```
internal/traversal/network_test.go:18:15: undefined: IPv4Address
internal/traversal/network_test.go:28:44: undefined: IPv4Address
internal/traversal/network_test.go:212:45: undefined: IPv4Address
internal/traversal/fingerprint_test.go:16:12: undefined: IPv4Address
internal/traversal/fingerprint_test.go:21:16: undefined: Fingerprint
internal/traversal/fingerprint_test.go:26:15: undefined: Fingerprint
FAIL    github.com/gxbrave/AntiNAT/internal/traversal [build failed]
```

GREEN: `Assess` is a pure function of an injectable `RouteTable` — no IPv4
addresses yields `V4_SOURCE_UNAVAILABLE`, no IPv4 default route yields
`V4_DEFAULT_ROUTE_UNAVAILABLE`, and a default-route interface holding only
private/CGNAT/link-local/documentation/reserved addresses yields
`NO_GLOBAL_V4_SOURCE`; only a global IPv4 on the *selected* default-route
interface yields `DIRECT_V4_READY`. All codes are stable across repeated
calls and independent of address order. `Fingerprint` hashes the canonical
(default route, interface addresses) text so route/interface changes are
detectable (v0.8 §2.3). The Linux host reader parses `/proc/net/route`
(lowest metric, lexicographic tie-break, little-endian hex gateways) and
lists IPv4 addresses of up, non-loopback interfaces; non-Linux builds return
`ErrUnsupportedPlatform` (no platform claims without native evidence).

Test fixture correction during GREEN: `TestAssessStableAcrossRepeatedCalls`
initially used `203.0.113.7` (TEST-NET-3 documentation space) as the
"global" source; the classifier correctly rejected it, so the fixture was
changed to `8.8.8.8` — the classifier behavior was right, the test data was
wrong.

## Story 2 — Atomic PortRegistry and OS single-instance lock

RED command: `GOWORK=off go test ./internal/traversal/ -count=1`

RED reason: the registry and instance-lock symbols were absent (feature
absent):

```
internal/traversal/portregistry_test.go:16:47: undefined: PortRegistry
internal/traversal/portregistry_test.go:16:90: undefined: Lease
internal/traversal/instance_lock_test.go:19:15: undefined: AcquireInstanceLock
internal/traversal/instance_lock_test.go:42:20: undefined: ErrInstanceLocked
internal/traversal/instance_lock_test.go:111:58: undefined: ErrInvalidLockPath
FAIL    github.com/gxbrave/AntiNAT/internal/traversal [build failed]
```

GREEN: `PortRegistry.Acquire` validates the tuple, checks overlap, creates
the actual socket, resolves the OS-assigned port, and publishes the entry in
one critical section (never bind→close→rebind). Port 0 resolves to the
actual port; wildcard/specific overlap, duplicate owner, and concurrent
contenders are rejected with `ErrTupleOverlap`; a stale release with a
mismatched owner/generation returns `ErrStaleLease` and can never close the
new owner; a failed OS close retains the entry. UDP/IPv6 tuples are rejected
with `ErrUnsupportedTuple` (P13 owns UDP). `AcquireInstanceLock` is the
Linux flock single-instance lock with O_NOFOLLOW, regular-file, parent-dir
ownership, and before/after inode checks; a second same-UID process is
blocked (`LOCK_BLOCKED` subprocess evidence) and an abrupt owner exit
releases the flock so a quick restart re-acquires immediately. Non-Linux
builds return `ErrUnsupportedPlatform`.

## Story 3 — TCP forwarding and half-close
(pending)
