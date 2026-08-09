# ADR-0004: Reproducible Go toolchain, CI, and evidence

- Status: accepted
- Date: 2026-08-09
- Owners: gxbrave

## Decision

The module path is `github.com/gxbrave/AntiNAT`. The repository declares
`go 1.26.0` with `toolchain go1.26.5`, the version verified from the official Go
distribution metadata during bootstrap. CI pins action references by commit SHA,
uses read-only permissions, fixed job timeouts, artifact retention, and separate
`pr-fast`, `pr-integration`, and `windows-pr` lanes.

Every evidence record is validated against `test/evidence/schema.json` and must
include a plan, 40-character commit SHA, exact command, result, and SHA-256
artifact digest. The validator emits stable error codes and exits non-zero for
malformed records.

## Rationale

A clean bootstrap must be reproducible without a dependency graph or network
service. Exact toolchain/action pins and machine-readable evidence keep later
release claims tied to the artifact actually tested.

## Consequences

Go module changes require an explicit reviewed update to this ADR and CI image.
Fork pull requests never receive secrets or privileged execution. A missing
artifact digest or unpinned action blocks integration rather than being waived.
