# v1.0-beta Release Checklist

This checklist is evaluated against one exact candidate bundle. The current
P19 candidate is not a published release: the repository has no production
signing key, independent release approver, controller endpoint, remote probe
vantage, native Windows/OpenRC lifecycle evidence, complete arm64 installer
evidence, registry digest, or 24-hour soak result. Native Debian 12 arm64
Controller/Agent startup and control-session checks are recorded, but do not
promote the full arm64 installer or data path. The release lane provisions the pinned browser suite and
`govulncheck`; their local results do not replace the external gates.

## Gates for the Debian/Ubuntu amd64 release

| Gate | Evidence requirement | Current candidate policy |
|---|---|---|
| `exact-build` | One clean-head build with full source identity | Required `PASS` |
| `windows-cmd-build` | Windows amd64 command binaries compile | Required `PASS`; no native runtime claim |
| `artifact-integrity` | Manifest and independent checksums match every byte | Required `PASS` |
| `signature` | Detached Ed25519 signature verifies with the pinned root | Required for promotion |
| `functional-e2e` | Controller, Agent, direct TCP/UDP, lifecycle and UI checks | Local evidence is retained with limits |
| `security` | Secret scan, fault boundaries, sandbox/SSRF and static checks | Required `PASS` |
| `install-upgrade-purge` | Fresh install, N/N-1 upgrade, rollback and residue scan | Required `PASS` |
| `real-wan` | Independent client/provider and restart/NAT matrix | Optional limitation; the release makes no public-WAN claim |
| `platform-matrix` | Native promoted platforms plus exact artifact checks | Optional limitation; only Debian/Ubuntu amd64 is in scope |
| `soak` | At least 24 hours on primary Linux with bounded resources | Optional limitation; no duration claim is made |
| `release-evidence` | Final verifier reads the unchanged manifest and bundle | Required `PASS` |

The required command shape is:

```sh
GOWORK=off go test -p 1 ./... -count=1
GOWORK=off go test -p 1 -race ./... -count=1
GOWORK=off go vet ./...
GOWORK=off govulncheck ./...
./scripts/run-beta-gates.sh --artifacts ./dist --evidence ./artifacts/evidence
go run ./scripts/verify-release-evidence.go ./artifacts/evidence
```

Use `--require-promotion` only in the protected promotion job. An unavailable
optional tool or external system is recorded as a limit; it is never replaced
by a fake WAN, loopback, cross-build, or local registry claim.

## Promotion review

The independent reviewer checks the source/tree identity, manifest and
signature bytes, all gate digests, support matrix, known limits, changelog,
rollback instructions, and secret scan. The reviewer must reject a bundle if
any required gate is `FAIL`, `NO_GO`, or `SUPPORTED_WITH_LIMITS`, if the
manifest is rebuilt after testing, or if the UI/README overstates support.

No tag, remote push, or release is performed by the P19 coding worker.
