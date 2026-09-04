# OCI packaging

The default `agent` target and the `controller` target are built from one
source tree with `CGO_ENABLED=0`, trimpath, and linker-injected build metadata.
Both run as UID/GID `65532`, use explicit volumes, and use host networking in
the compose profile because AntiNAT's data-plane bind is host-facing.

Release automation must push by immutable version tag, resolve and record the
resulting `sha256:` image digest, generate an SBOM, and sign the digest. A
mutable `:latest` tag is not release evidence and is not used by P17's final
acceptance claim.
