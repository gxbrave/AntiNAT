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
new owner; a failed OS close (other than `net.ErrClosed`, where the
descriptor is provably gone) retains the entry. UDP/IPv6 tuples are rejected
with `ErrUnsupportedTuple` (P13 owns UDP). `AcquireInstanceLock` is the
Linux flock single-instance lock with O_NOFOLLOW, regular-file, parent-dir
ownership, and before/after inode checks; a second same-UID process is
blocked (`LOCK_BLOCKED` subprocess evidence) and an abrupt owner exit
releases the flock so a quick restart re-acquires immediately. Non-Linux
builds return `ErrUnsupportedPlatform`.

## Repair cycle 1 (FIX1) — review findings

FINDING F1 (QUALITY): `IPv4Addresses()` dropped every IPv4 address on
IPv6-enabled hosts. Interface address lists deliver IPv4 as 16-byte
IPv4-mapped addresses (`::ffff:x.x.x.x`); `netip.AddrFromSlice` returns
those in IPv6 form, so the `Is4()` gate ran before `Unmap()` and filtered
everything out.

RED command: `GOWORK=off go test ./internal/traversal -run 'TestIPv4AddressesAcceptsMappedInput|TestUsableV4RejectsNonV4' -count=1`

RED reason: the mapped-address seam was absent (feature absent):

```
internal/traversal/socket_linux_test.go:19:13: undefined: usableV4
internal/traversal/socket_linux_test.go:27:12: undefined: usableV4
internal/traversal/socket_linux_test.go:39:12: undefined: usableV4
FAIL	github.com/gxbrave/AntiNAT/internal/traversal [build failed]
```

GREEN: `usableV4` runs `Unmap()` before the `Is4()` gate and is used by
`IPv4Addresses()`; the 16-byte mapped fixture `net.IPv4(192,168,6,99)`
resolves to canonical `192.168.6.99`.

GREEN verification of the no-skip host test: with the pre-fix gate
restored, `TestHostRouteTableDeterministic` FAILS on the live host instead
of skipping:

```
    socket_linux_test.go:151: host must expose at least one non-loopback IPv4 address (F1 regression: IPv4-mapped addresses were silently dropped)
--- FAIL: TestHostRouteTableDeterministic (0.00s)
```

Post-fix the test passes and exercises the real host IPv4 (ens18
`192.168.6.99`).

FINDING F1 (NETWORK): ghost `PortRegistry` entry broke delete→recreate.
Composing the documented delete flow — `Forward.Close()` then
`lease.Release()` — made `Release` return `net.ErrClosed`; the fail-safe
retained the registry entry and re-acquiring the same tuple failed with
`ErrTupleOverlap` until process restart.

RED command: `GOWORK=off go test ./internal/traversal -run TestReleaseAfterExternalCloseFreesTuple -v -count=1`

RED reason: the regression test asserts the required lifecycle and fails on
the ghost behavior (bug present):

```
    portregistry_test.go:141: release after external close: close tcp4 127.0.0.1:35963: use of closed network connection
--- FAIL: TestReleaseAfterExternalCloseFreesTuple (0.00s)
```

GREEN: `Lease.Release` treats `errors.Is(err, net.ErrClosed)` as a
successful close — the descriptor is provably gone — and deletes the
entry; acquire→Close→Release→re-acquire now succeeds while the generation
guard still makes stale releases inert.

FINDING F3 (NETWORK): `IsGlobalV4` missed four IANA special-purpose
prefixes (deprecated 6to4 relay anycast `192.88.99.0/24` RFC 7526; direct
delegation AS112 `192.31.196.0/24` and `192.175.48.0/24` RFC 7534; AMT
default relay `192.52.193.0/24` RFC 7450).

RED command: `GOWORK=off go test ./internal/traversal -run TestIsGlobalV4Classification -v -count=1`

RED reason: the new rows were misclassified as global (bug present):

```
    network_test.go:70: IsGlobalV4(192.88.99.1) = true, want false
    network_test.go:70: IsGlobalV4(192.31.196.1) = true, want false
    network_test.go:70: IsGlobalV4(192.175.48.1) = true, want false
    network_test.go:70: IsGlobalV4(192.52.193.1) = true, want false
--- FAIL: TestIsGlobalV4Classification (0.00s)
```

GREEN: the four prefixes joined `nonGlobalV4Prefixes`; all rows pass.
`255.255.255.255/32` needs no new exclusion — `240.0.0.0/4` already covers
it (existing test row passes).
