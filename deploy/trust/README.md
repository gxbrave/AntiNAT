# Release trust root

`release-ed25519.pub` is the pinned public verification key for the example
release channel (`trust_root=release-key-2026`). The corresponding private key
is never stored in this repository. Production release automation supplies the
private key out of band and publishes `manifest.json` plus its detached
`manifest.sig` before uploading artifacts.

The installer accepts `ANTINAT_TRUST_ROOT_FILE` so an operator can replace this
development root with the separately distributed production root. It never
uses a checksum downloaded from the same untrusted URL as a trust anchor.
