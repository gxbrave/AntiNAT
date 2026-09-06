# AntiNAT

AntiNAT is a Go-based Controller and Agent system for evidence-backed IPv4
endpoint publication and forwarding. The Controller owns management state,
authentication, the control plane, health, and audit data. The Agent owns
local sockets, traversal attempts, and user traffic. The Controller never
relays user payloads.

This repository is the integrated source tree for the Controller product. It
also keeps the Agent implementation and cross-component tests needed to
validate the complete system. A standalone Agent distribution is published at
`github.com/gxbrave/AntiNAT-Agent`.

## Status

The source tree is the P19 beta candidate published from the completed local
development workspace. It is classified `SUPPORTED_WITH_LIMITS`:

- Linux amd64 build, local functional tests, race tests, vet, browser checks,
  and isolated installer checks are covered by the repository gates.
- Independent public-WAN, real CPE/router, native Windows, native arm64/OpenRC,
  registry OCI digest, production signing, and 24-hour soak evidence are not
  available for this candidate.
- No `v1.0.0-beta.1` release tag or GitHub Release is claimed until those
  external gates and a production signing approval are supplied.

The support classification is documented in `docs/support-matrix.md` and the
release policy in `docs/release-policy.md`.

## Build and test

The repository uses Go 1.26.6 as its validated toolchain.

```bash
GOWORK=off make check
GOWORK=off make build
GOWORK=off make verify-evidence
./bin/antinat-controller version
./bin/antinat-agent version
```

The full beta evidence lane is available locally:

```bash
GOWORK=off bash scripts/run-beta-gates.sh \
  --artifacts ./dist \
  --evidence ./artifacts/evidence
GOWORK=off go run ./scripts/verify-release-evidence.go ./artifacts/evidence
```

Some sandbox tests require the documented dedicated identity:

```bash
ANTINAT_DEDICATED_UID=12001 \
ANTINAT_DEDICATED_GID=12001 \
GOWORK=off make check
```

## Components

- `cmd/antinat-controller`: Controller HTTP service and API.
- `cmd/antinat-agent`: integrated Agent process.
- `cmd/antinatctl`: operator CLI.
- `cmd/antinat-probe`: independent probe service used by WAN evidence.
- `cmd/antinat-hook-runner`: isolated hook runner.
- `internal/protocol`: signed Controller-Agent wire protocol.
- `internal/controller`: durable Controller state, API, probes, lifecycle, and
  web UI.
- `internal/agent`: local Agent state, reconciliation, enrollment, and
  lifecycle handling.

## Security and scope

AntiNAT is a clean-room implementation distributed under the Apache License
2.0. `antinat.txt` records inspiration and scope boundaries; no Natter source
or GPL-3.0 implementation is included.

Only an authenticated probe from a named independent vantage can establish
`OPEN_FROM_VANTAGE`. A local bind, STUN mapping, loopback test, cross-build, or
fake server never upgrades that evidence level.
