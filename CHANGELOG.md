# Changelog

## v1.0.0-beta.1 candidate

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
- Added the raw GitHub Debian/Ubuntu bootstrap form:
  `bash <(curl -Ls https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh)`.
- Added Linux arm64 release artifacts and architecture-aware installer
  selection. Windows remains build-only pending a native test host.
- Updated the Windows command-line installer to target the same beta release
  URL as the Linux bootstrap.

The candidate is not published by the coding worker. Promotion still requires
the protected Ed25519 signing key, an independent approval, and the external
gates listed in the release evidence record.
