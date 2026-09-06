# Changelog

## v1.0.0-beta.1 candidate

- Added exact-artifact P19 release evidence validation and immutable manifest
  checks.
- Added one-time Debian/Ubuntu Linux amd64 release orchestration, checksums,
  CycloneDX SBOM metadata, and detached Ed25519 signing when the protected key
  is available.
- Added a Windows amd64 command-line cross-build check without claiming native
  Windows runtime support.
- Added release-gate evidence for functional tests, installers, security,
  platform limits, independent WAN prerequisites, and the 24-hour soak.
- Added a protected GitHub Actions promotion workflow that never rebuilds a
  verified candidate.
- Documented truthful NAT, platform, support, rollback, and promotion limits.
- Added the raw GitHub Debian/Ubuntu bootstrap form:
  `bash <(curl -Ls https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh)`.
- Kept Linux arm64 and Windows artifacts outside the first release until native
  platform evidence is available.

Publication is performed by the protected promotion workflow after the exact
manifest is signed and the required gates in the release evidence record pass.
