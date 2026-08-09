# M0 network feasibility summary (P02)

## Decision

Overall result: **SUPPORTED_WITH_LIMITS**.

The Linux socket, registry, UDP, and provider-hidden challenge fixtures passed. The privileged lab used real miniupnpd 2.3.4 (nftables backend), miniupnpc 2.2.6, and coturn 4.6.1 across four Linux network namespaces. It produced an intentional **NO_GO** for a restrictive CPE→CGN layered mapping: miniupnpd observed a different upstream STUN tuple and refused the UPnP mapping with `501 Action Failed`. This is evidence that `FIRST_HOP_MAPPED` must not become verified, not evidence of WAN reachability.

No native Windows host, physical CPE/router, or independent remote WAN vantage was available. Cross-compilation and same-host namespaces do not replace those missing evidence classes.

## Classification matrix

| Spike | Result | Reproducible evidence | Exact fallback / P04 input |
|---|---|---|---|
| Linux TCP shared port | PASS | `tcp-shared-port-linux.json` | Linux may keep `stun-tcp-shared-port` behind a process lock. Every listener/connected participant needs pre-bind `SO_REUSEADDR` + `SO_REUSEPORT`; the listener alone is not an ownership boundary. |
| Windows TCP shared port | SUPPORTED_WITH_LIMITS | `tcp-shared-port-windows.json` | Cross-build only. Disable Windows `stun-tcp-shared-port` until the native baseline, listener + multiple connected sockets, half-close, restart, and stale-process gates execute successfully. |
| Atomic PortRegistry / process ownership | SUPPORTED_WITH_LIMITS | `port-registry.json` | Linux socket-owning acquire is feasible. Bind/listen must happen inside the registry critical section; port 0 is resolved before publication; wildcard overlap and owner generation are mandatory; stale release cannot close a new owner. `SO_REUSEPORT` makes a second process able to join, so stop-old-before-start-new plus an OS single-instance lock is mandatory. Windows remains unpromoted. |
| UDP single socket | SUPPORTED_WITH_LIMITS | `udp-single-socket.json` | Linux fixture passed strict STUN/probe/data demux, bounded sessions, truncation survival, post-ICMP receive, and exact-source target reply. Windows UDP stays disabled until native `WSAECONNRESET` / `SIO_UDP_CONNRESET` execution passes. |
| Provider-hidden challenge | PASS | `hidden-challenge.json` | Freeze arm→armed→provider frame→same-path ACK + signed control receipt. Arm contains no challenge. Join only one probe ID, activation, endpoint, provider, opaque expiry, challenge hash, and TTL window. Invalid ingress exposes one generic rejection; replay and attempt budgets are mandatory. This is protocol feasibility, not independent-WAN evidence. |
| Layered CPE→CGN | NO_GO | `layered-nat.json` | The real daemon detected restrictive/symmetric upstream NAT and blocked the mapping. v1 must retain at most one tested explicit mapping layer plus an observed STUN layer, classify the gateway tuple as `FIRST_HOP_MAPPED`, and require `OPEN_FROM_VANTAGE` before verified publication. Multiple explicit NAT control layers remain unsupported. |
| Mapping ownership | SUPPORTED_WITH_LIMITS | `mapping-ownership.json` | PCP=`STRONG_PROTOCOL_OWNERSHIP`; NAT-PMP=`WEAK_LEASE_OWNERSHIP` and internal port 0 delete is forbidden; UPnP=`BEST_EFFORT_QUERY_THEN_DELETE` and all external port/protocol/internal client/internal port/description fields must match. Real CPE deletion/TOCTOU evidence is still absent, so adapters remain experimental. |

## Linux TCP conclusions

The baseline listener plus an outgoing socket bound to the same local tuple fails with `EADDRINUSE` when the required pre-bind options are absent. On Linux 6.8, a unique listener and three established connections to distinct remote tuples route deterministically when all participants set `SO_REUSEADDR` and `SO_REUSEPORT` before bind. Remote `CloseWrite` preserves the local write half, and closing the fixture allows an exact-tuple rebind.

A second process can also join the reuse group. Therefore the reusable socket options are a transport mechanism only; they must never represent ownership. The process-lock test proves a separate `flock(LOCK_EX|LOCK_NB)` gate blocks a concurrent installer/Agent process. The lock file remains in place after unlock to avoid inode-replacement races.

## UDP conclusions

The fixture accepts a STUN response only when transaction ID, exact server tuple, class, and deadline all match an outstanding request. It accepts a probe only when provider source, signature, probe ID, activation, endpoint, challenge, and deadline all match. Lookalikes and expired/wrong frames are routed as data (subject to the bounded session table), never consumed as control traffic.

Target responses use the original unconnected ingress socket, preserving the published source tuple. Truncated datagrams are dropped and counted; the next datagram remains readable. The localhost ICMP trigger did not surface as a socket error on this Linux kernel, but the unconnected receive loop remained alive and accepted the following datagram. This must not be generalized to Winsock without native evidence.

## Hidden-challenge conclusions

The signed control arm contains provider identity/key, expected source policy, probe ID, activation, exact endpoint, TTL, and opaque expiry, but no provider challenge. The provider signs the full WAN frame and introduces the challenge only at ingress. The Agent signs both a same-path ACK and a control receipt bound to the challenge hash. A control-only malicious Agent that guesses a challenge cannot satisfy the Controller join.

The TCP fixture returns the ACK on the accepted ingress connection. The UDP fixture returns the ACK from the exact published socket and keeps the response smaller than the request. Wrong source, activation, endpoint, opaque expiry, signature, TTL, replay, and over-budget attempts all produce the same public `REJECTED` outcome with no authenticated response material.

## Layered NAT lab scope

Topology:

```text
Agent 10.0.0.2
  -> CPE miniupnpd 10.0.0.1 / 100.64.0.2
  -> restrictive CGN 100.64.0.1 / 11.0.0.2
  -> coturn STUN vantage 11.0.0.1
```

`11.0.0.0/24` exists only inside isolated namespaces so miniupnpd's public-address checks exercise the layered path; it is not routed or claimed as an owned Internet range. This same-host namespace is not an independent WAN vantage. The observed upstream tuple changes on each run and is retained in `raw/layered-nat.log`. Cleanup traps remove daemon processes and all namespaces on success, failure, interrupt, or timeout; the Go test verifies no `antinat-p02-*` namespace remains.

## Commands

```text
go test ./spike/network/... -count=1 -v
go test -tags=netns ./spike/network/... -count=1 -v
GOOS=windows GOARCH=amd64 go test -c -o <temporary>/network.test.exe ./spike/network
for record in test/evidence/m0/network/*.json; do [ "$record" = .../environment.json ] || go run ./scripts/verify-evidence.go "$record"; done
```

The child-plan literal `go run ./scripts/verify-evidence.go ./test/evidence/m0/network` cannot validate a directory because the integrated P01 validator accepts exactly one record path. P02 therefore validates every evidence JSON individually without changing the P01-owned validator.

## Evidence index

- `test/evidence/m0/network/environment.json`: host/tool/daemon manifest and missing-resource declarations.
- `test/evidence/m0/network/raw/tdd-red.md`: observed RED failures and expected reasons.
- `test/evidence/m0/network/*.json`: schema-valid classifications pinned to tested commit `6c7a223aa6950cd3c5ddeca23abf2c2626207a66`.
- `test/evidence/m0/network/raw/*.log`: exact test output and exit codes hashed by each evidence record.

Spike code is disposable evidence code. Later plans must consume these conclusions and must not copy it into production packages.
