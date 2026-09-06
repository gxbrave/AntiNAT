# AntiNAT

[中文说明](README.md)

AntiNAT is an IPv4 public-access tool built around a Controller and Agents. The Controller manages configuration, nodes, authentication, and reachability evidence. An Agent runs inside the target network and handles mappings, NAT traversal, and real TCP/UDP traffic. The Controller does not relay business traffic.

This repository is the integrated Controller tree. It also contains an integrated Agent and cross-component tests. The standalone Agent project is [gxbrave/AntiNAT-Agent](https://github.com/gxbrave/AntiNAT-Agent).

## What It Does

- Manage Agent nodes and TCP/UDP forwarding rules from the web UI, HTTP API, or `antinatctl`.
- Try direct, STUN, PCP, NAT-PMP, and UPnP paths from the Agent and report the result to the Controller.
- Deliver configuration, heartbeats, and lifecycle operations over a signed Controller-Agent control channel.
- Keep durable local state across restarts, failed updates, and recovery.
- Run constrained Webhook/script hooks and keep reachability evidence separate from simple local observations.

## Components

| Path or command | Purpose |
| --- | --- |
| `cmd/antinat-controller` | Controller HTTP service |
| `cmd/antinat-agent` | Integrated Agent process |
| `cmd/antinatctl` | Admin CLI |
| `cmd/antinat-probe` | Independent probe service |
| `cmd/antinat-hook-runner` | Isolated hook runner |
| `internal/controller` | Controller state, API, probing, lifecycle, and web UI |
| `internal/agent` | Agent control session, local state, and forwarding coordination |
| `internal/protocol` | Signed Controller-Agent protocol |
| `scripts/` and `deploy/` | Build checks, installers, services, and release trust files |

## Support Limits

The first `v1.0.0-beta.1` artifacts target Linux amd64 on Debian 12 and Ubuntu 22.04/24.04. Local functional tests, race tests, static checks, browser checks, and isolated installer tests are covered; public-NAT, long-running, and other-platform limits remain explicit below.

- Linux amd64 is the first Debian/Ubuntu beta target, with systemd as the primary installer path.
- Linux arm64 keeps cross-build support, but the ARM host is outside this release's validation scope.
- Windows amd64 is only required to start through `cmd` and pass build checks; it is not part of the first Debian/Ubuntu release support scope.
- OpenRC, real public WAN and CPE/router evidence, registry OCI digests, and long-running soak evidence are still missing.
- v1 does not promise arbitrary-NAT reachability, Controller traffic relay, IPv6 forwarding, or a formal `2 Gbps`/`<1 ms` SLO.

## Getting Started

### Requirements

- Debian 12, Ubuntu 22.04, or Ubuntu 24.04 on Linux amd64.
- Go 1.26.6, or a CI-compatible Go version.
- `bash`, `jq`, and other common build tools; the full installer checks require root privileges.

### Option 1: Installer script

The installer downloads a signed release manifest and artifacts, verifies the trust root and SHA-256 digests, then installs a systemd/OpenRC service. Agent enrollment tokens are read from a hidden TTY or a `0600` file/file descriptor. Never put a token directly in the command line.

After `v1.0.0-beta.1` is published, run the following directly on the target Debian/Ubuntu host. It downloads signed artifacts and installs the Controller and Agent:

```bash
sudo env ANTINAT_ROLE=both \
  bash <(curl -Ls https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh) install \
  --controller-endpoint https://your-controller.example
```

For networks that need a GitHub mirror, set the release URL prefix while keeping the same raw command:

```bash
sudo env ANTINAT_ROLE=both \
  ANTINAT_RELEASE_BASE_URL="https://ghfast.top/https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta.1" \
  bash <(curl -Ls https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh) install \
  --controller-endpoint https://your-controller.example
```

`ANTINAT_RELEASE_BASE_URL` is the right setting for this URL-prefix mirror. `--github-proxy` is for a real HTTP(S) proxy server and is a different option. Use `ANTINAT_ROLE=controller` for only the Controller or `ANTINAT_ROLE=agent` for only the Agent. The first release installer targets Linux amd64; see [`docs/installer-contract.md`](docs/installer-contract.md).

### Option 2: Build from source

```bash
git clone https://github.com/gxbrave/AntiNAT.git
cd AntiNAT
GOWORK=off make check
GOWORK=off make build
./bin/antinat-controller version
./bin/antinat-agent version
```

Start a local Controller:

```bash
./bin/antinat-controller \
  --listen 127.0.0.1:3111 \
  --store ./var/controller.db \
  --keydir ./var/keys
```

In another terminal, initialize an admin and create a node:

```bash
GOWORK=off go build -o bin/antinatctl ./cmd/antinatctl
./bin/antinatctl --endpoint http://127.0.0.1:3111 admin init
./bin/antinatctl --endpoint http://127.0.0.1:3111 login --username admin
./bin/antinatctl --endpoint http://127.0.0.1:3111 node create --name agent-1
./bin/antinatctl --endpoint http://127.0.0.1:3111 node list
```

Give the Agent its node ID, one-time enrollment token, and the Controller public-key pin. Store the token in a `0600` file; a successful enrollment consumes it:

```bash
chmod 600 ./var/enrollment.token
./bin/antinat-agent \
  --endpoint http://127.0.0.1:3111 \
  --node <node-id> \
  --token-file ./var/enrollment.token \
  --pin <64-hex-character-controller-public-key> \
  --state ./var/agent
```

The same values can be supplied through `ANTINAT_ENDPOINT`, `ANTINAT_NODE`, `ANTINAT_TOKEN_FILE`, `ANTINAT_PIN`, and `ANTINAT_STATE`.

### Useful checks

```bash
GOWORK=off make verify-evidence
GOWORK=off go run ./scripts/verify-release-evidence.go ./artifacts/evidence
curl http://127.0.0.1:3111/healthz
curl http://127.0.0.1:3111/readyz
```

The full beta gate is available locally:

```bash
GOWORK=off bash scripts/run-beta-gates.sh \
  --artifacts ./dist \
  --evidence ./artifacts/evidence
```

## Implementation

The Controller and Agent are separate fault domains. The Controller stores desired state and handles authentication, the web/API surface, node management, probe coordination, and audit data. The Agent owns local listeners, mappings, forwarding, and recovery. Business payloads stay in the Agent data plane.

The control channel uses signed protocol frames and node identity. Agent changes pass through a durable local reconciler, so updates, deletion, restart recovery, and rollback have explicit states. Public reachability requires an authenticated probe from a named independent vantage; a local bind, STUN mapping, or public-IP lookup is only a candidate observation.

The installer downloads the release manifest, signature, and artifacts, verifies the pinned trust root and SHA-256 digests, and installs files atomically. More detailed protocol, state-machine, and security rules are in `docs/`.

## Tests

```bash
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

Some sandbox tests need a dedicated identity:

```bash
ANTINAT_DEDICATED_UID=12001 \
ANTINAT_DEDICATED_GID=12001 \
GOWORK=off make check
```

## License

This project is released under the [GPL-3.0](LICENSE).
