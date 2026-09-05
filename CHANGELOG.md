# Changelog

## Unreleased beta candidate

- Added exact-artifact P19 release evidence validation and immutable manifest
  checks.
- Added one-time Linux amd64 release orchestration for Linux/Windows binary
  candidates, checksums, CycloneDX SBOM metadata, and detached Ed25519 signing
  when the protected key is available.
- Added release-gate evidence for functional tests, installers, security,
  platform limits, independent WAN prerequisites, and the 24-hour soak.
- Added a protected GitHub Actions promotion workflow that never rebuilds a
  verified candidate.
- Documented truthful NAT, platform, support, rollback, and promotion limits.

The current candidate is not a published `v1.0.0-beta.1` release. It remains
`SUPPORTED_WITH_LIMITS` until the missing release inputs and required external
gates are supplied and independently approved.
