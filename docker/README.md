# OCI packaging

The default `agent` target and the `controller` target are built from one
source tree with `CGO_ENABLED=0`, trimpath, and linker-injected build metadata.
Both run as UID/GID `65532`, use explicit volumes, and use host networking in
the compose profile because AntiNAT's data-plane bind is host-facing.

## Compose enrollment

The Agent receives an enrollment token through a Compose file-backed secret.
Set `ANTINAT_ENROLLMENT_TOKEN_FILE` to a protected host path, then provide the
endpoint, node id, and pinned Controller key:

```sh
export ANTINAT_ENROLLMENT_TOKEN_FILE=/secure/antinat/enrollment.token
export ANTINAT_ENDPOINT=https://controller.example
export ANTINAT_NODE=node-1
export ANTINAT_PIN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
docker compose -f docker/compose.yaml up -d
```

The wrapper copies the read-only secret into the private Agent state volume as
an owner-only file. The Agent consumes and removes that staged file after a
successful enrollment; a completion marker prevents a restart from attempting
enrollment again. The host source is operator-owned and is never copied into an
image layer or placed in a command line/environment variable. Keep it
protected, and remove it from the host after the enrollment token has been
consumed if the deployment no longer needs it.

The mounted source secret is intentionally not used as the Agent's token path:
Docker manages it as read-only, while the staged copy follows the Agent's
normal 0600 validation and deletion path. A fresh enrollment requires a fresh
Agent state volume and a new Controller-issued token.

## Release evidence

Release automation must push by an immutable version tag, resolve and record
the resulting registry `sha256:` manifest digest, generate an SBOM for the
digest, and sign and verify that exact digest. The command shape is:

```sh
IMAGE_REF=ghcr.io/example/antinat-agent:1.0.0
docker buildx build --platform linux/amd64 --target agent --tag "$IMAGE_REF" --push .
DIGEST="$(docker buildx imagetools inspect "$IMAGE_REF" --format '{{.Manifest.Digest}}')"
syft "$IMAGE_REF@$DIGEST" -o spdx-json > antinat-agent.sbom.spdx.json
cosign sign --yes "$IMAGE_REF@$DIGEST"
cosign verify "$IMAGE_REF@$DIGEST"
```

A local `docker build --load` image ID is not registry digest evidence, and a
mutable `:latest` tag is never release evidence. The platform workflow records
these distinctions and emits `SUPPORTED_WITH_LIMITS` when the daemon, SBOM
tool, registry digest, or signing tool is unavailable.
