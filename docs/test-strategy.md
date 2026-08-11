# AntiNAT Test Strategy Contract (FROZEN)

> Status: **FROZEN at P04**. This document defines the mandatory test
> strategy, required commands, evidence rules, and CI lanes that later plans
> must follow. It does not grant later plans permission to change frozen
> contracts.

## 1. Scope

This contract freezes:

1. The RED→GREEN→REFACTOR discipline for every behavioral Story.
2. The required verification commands and their exit-code gates.
3. The evidence schema and anti-fabrication rules.
4. The CI lane matrix and its resource/time limits.
5. The definition of honest capability promotion.

## 2. Development discipline

- Strict RED→GREEN→REFACTOR for every behavioral Story; no production code
  before its focused failing test.
- One observable behavior per test; tests assert behavior, not implementation.
- Real infrastructure is required for the claimed evidence class. Missing
  infrastructure downgrades the capability; it never permits fake PASS
  evidence.
- Infrastructure failures may retry once; deterministic failures never retry
  to green.

## 3. Required commands

Cumulative suite (run at each integration point, from the exact head):

```bash
go test ./test/contracts/... -count=1 -v          # frozen-contract gate
go test ./...                                      # unit + package suites
go test -race ./... -count=1                       # race detector
go vet ./...                                       # static analysis
govulncheck ./...                                  # vulnerability scan (release lane)
make test && make check && make build              # aggregate targets
python3 test/contracts/validate_openapi.py .       # OpenAPI/error-code gate
```

Golden-corpus gates (once implemented by later plans):

```bash
go test ./internal/protocol -run 'Test(ControlEnvelope|Enrollment|Probe)Golden' -count=1
go test ./test/e2e -run TestLinuxDirectV4WalkingSkeleton -count=1 -v
sudo -E go test -tags=netns ./test/integration/... -count=1 -v
```

Native Windows/OpenRC/arm64 and real-WAN tests can never be replaced with
cross-builds. Cross-build evidence is labeled `build-only` and never promoted
to native status.

## 4. Evidence rules

Every evidence JSON record contains at minimum: commit SHA, artifact digest,
OS/kernel/build, architecture, hardware/router/firmware, command, start/end
monotonic duration, result, assertions, log/pcap hashes, approver, and
capability promotion level.

- No fabricated network, platform, hardware, benchmark, test, or release
  evidence.
- `test/evidence/schema.json` (P01-owned) is the evidence schema; every record
  validates against it.
- Evidence records are pinned to the exact commit/tree SHA and to the artifact
  digest; a post-test rebuild invalidates the evidence.
- Evidence claims never exceed what the record proves (e.g., same-host
  namespaces are never "independent WAN evidence").

## 5. CI lanes

| Lane | Contents | Limits |
|---|---|---|
| `pr-fast` | gofmt, unit, golden, store, vet/static, cross-build, license | <10m; no privilege/secret |
| `pr-integration` | enroll/control/LKG/direct TCP, delete, race subset | fixed timeout; failure uploads state/log |
| `windows-pr` | Winsock, DPAPI/ACL, Service parser, Defender, UDP ICMP | native Windows only |
| `nightly-privileged` | netns, fuzz, installer VM, fault injection | self-hosted isolation; no fork PRs |
| `weekly-dedicated` | real router, arm64/OpenRC, Windows service, short perf | environment manifest + raw evidence |
| `release` | real WAN/NAT, full perf, 24h soak, artifact install/purge | manual approval; immutable digest |

## 6. Honest capability promotion

- `PASS`: real evidence on the target platform at the claimed level.
- `SUPPORTED_WITH_LIMITS`: evidence exists with explicit, non-blocking limits
  (e.g., Linux-only, lab-only).
- `NO_GO` / `UNSUPPORTED`: missing evidence or a failed gate; the capability is
  feature-gated or removed, never shown as supported.
- `build-only` / `experimental`: cross-build or prototype evidence only; never
  promoted without native/real evidence.
