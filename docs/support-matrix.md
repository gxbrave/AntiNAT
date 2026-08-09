# AntiNAT support matrix

Status date: 2026-08-09

The status column is the intended v1.0-beta release classification, not a claim
that P01 already implements the capability. The current evidence column is
intentionally explicit so a bootstrap build cannot be mistaken for support.

| Capability / platform | v1 status | Required evidence gate | Current P01 evidence |
|---|---|---|---|
| Controller/Agent build on Linux amd64 | `beta` | Go build, package tests, startup/readiness and release artifact checks | Bootstrap binaries only; no service composition |
| Linux amd64 direct/manual TCP forwarding | `beta` | P10 Linux direct-v4 walking-skeleton E2E with independent probe and target response | Not implemented |
| Linux amd64 UDP forwarding | `beta` | P13 bounded mux/session/ICMP/MTU E2E and crash tests | Not implemented |
| Linux arm64 runtime | `experimental` | P18 real arm64 host install/restart/upgrade/purge evidence | Build target not yet exercised |
| Windows amd64 runtime | `build-only` | P18 real Windows service/ACL/Defender and data-path evidence | No Windows runtime evidence |
| Docker on Linux host network | `experimental` | OCI image, non-root runtime, state volume, SBOM/signature and host-network E2E | No OCI artifact |
| macOS runtime | `unsupported` | Not applicable to v1 | Excluded |
| Windows containers | `unsupported` | Not applicable to v1 | Excluded |
| IPv4 Controller control plane | `beta` | P08 signed control, reconnect, readiness and release tests | Not implemented |
| IPv6 Controller control connection | `beta` | Control-plane dual-stack tests on named OS targets | Not implemented |
| IPv4 Forward ingress and target | `beta` | P09/P10 protocol and direct-v4 E2E evidence | Not implemented |
| IPv6 Forward data plane | `unsupported` | v2 contract required | Excluded |
| Direct-v4 strategy | `beta` | Global source address + exact bound port + independent WAN probe | Not implemented |
| STUN-only strategy | `experimental` | P02/P11 real protocol and server-cooldown evidence | Not implemented |
| PCP / NAT-PMP / UPnP gateway layers | `experimental` | Per-adapter fake faults plus real daemon/CPE evidence | Not implemented |
| Controller business relay | `unsupported` | Separate future product and threat model required | Explicitly excluded |
| Runtime zero-copy claim | `experimental` | P03 lab instrumentation and exact artifact evidence | No claim permitted |
| Webhook hooks | `beta` | P16 SSRF, secret lifecycle, retry and delivery evidence | Not implemented |
| Arbitrary local shell hook | `unsupported` | Explicitly excluded for security | Explicitly excluded |
| Linux systemd install/upgrade/purge | `beta` | P18 fresh install, restart, rollback, purge on named distro | No installer |
| OpenRC installer | `experimental` | Real arm64/OpenRC host evidence | No installer |
| Formal 2 Gbps / `<1 ms` SLO | `unsupported` | Dedicated lab and approved performance contract required | Not a v1 claim |

## Promotion rules

A capability may be promoted only when the named gate produces a
machine-readable evidence record with an exact artifact digest. Cross-building
for another OS, testing only a fake service, reading a public IP API, or
observing a local bind cannot promote a runtime capability. Missing hardware or
vantage infrastructure lowers the status and is retained as a known limit.

The UI and README must use this matrix without inventing a broader status. Any
future status change updates this file, the requirements traceability, the
relevant ADR/contract, and the release evidence in one reviewed change.
