# OCI packaging

Controller and Agent use separate images and processes. The default Compose file
starts only the Controller from its published image; no Agent token is required:

```sh
docker compose -f docker/compose.yaml up -d
```

The Controller listens on port 3111 and stores its database in the Controller
volume. To install an Agent (including one on the same host), create a node in
the Controller and run its generated installation command yourself. The shell
installer's automatic local-Agent workflow is not used for Docker.

The `controller` image contains only the Controller binary. The separate `agent`
image contains the Agent and hook runner. Both use UID/GID 65532. A separately
installed Docker Agent receives endpoint, node ID and Controller pin from the
Controller and a token through a protected file; see the AntiNAT-Agent project.

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
