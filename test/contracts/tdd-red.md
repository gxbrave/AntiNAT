# P04 per-Story TDD RED evidence

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent reasons.

## Story 1 — Normative control/enrollment bytes

RED command: `go test ./test/contracts/... -run TestControlEnvelope -count=1 -v`
RED reason: no golden fixtures existed under
`internal/protocol/testdata/control-envelope/`:

```
control_envelope_test.go:74: no control-envelope fixtures found under
  internal/protocol/testdata/control-envelope
```

GREEN: generated 4 valid + 15 invalid golden vectors (framing/header/
consistency/signature reject stages); reference encoder/parser added.

Second RED (ambiguous JSON): `TestControlEnvelopeRejectsAmbiguousJSON` failed
because a nil schema rejected arbitrary keys:

```
control_envelope_test.go:218: baseline valid payload rejected: unknown JSON field "a"
```

GREEN: nil schema is treated as shape-only (any key allowed with unconstrained
kind); schema-present unknown fields still rejected.

## Story 1b — Enrollment transcript

RED command: `go test ./test/contracts/... -run TestEnrollment -count=1 -v`
RED reason: no enrollment fixtures:

```
enrollment_test.go:36: no enrollment fixtures found under
  internal/protocol/testdata/enrollment
```

GREEN: 3 valid + 8 invalid transcript vectors; reference encoder/parser.

## Story 2 — Probe wire and operation contract

RED command: `go test ./test/contracts/... -run TestProbe -count=1 -v`
RED reason: no probe-frame fixtures:

```
probe_test.go:55: no probe-frame fixtures found under
  internal/protocol/testdata/probe-frame
```

GREEN: ARM1/RDY1/WAN1/ACK1/RCT1 golden frames, invalid structural vectors, and
six operation transcripts exercising the frozen probe state machine.

## Story 3 — State and lifecycle contract

RED command: `go test ./test/contracts/... -run TestStateModel -count=1 -v`
RED reason: no state-model fixtures (initially a walk error on the missing
directory, then a clean "no fixtures" after tolerating absent dirs):

```
state_model_test.go:38: no state-model fixtures found under
  .../test/contracts/testdata/state-model
```

GREEN: 43 fixtures pinning FSM transitions (allowed + illegal), snapshots,
publication invariants, AppliedForwardState.

## Story 4 — OpenAPI / error / idempotency

RED command: `go test ./test/contracts/... -run TestOpenAPI -count=1 -v`
RED reasons (two rounds):
1. `DELETE /api/v1/forwards/{id} must require If-Match` — parameter $refs were
   not resolved before checking operation parameter names.
2. `registered error statuses unreachable in OpenAPI: ['400','403','413',
   '429','500','501']` — the OpenAPI did not yet reference every registered
   error status.

GREEN: parameter $ref resolution in the validator; added 400/403/413/429/500/
501 responses to the appropriate operations.

## Story 5 — Installer and compatibility contract

RED command: `go test ./test/contracts/... -run TestInstaller -count=1 -v`
RED reason: no installer/compat fixtures:

```
installer_test.go:79: no installer/compat fixtures found under
  [.../test/fixtures/installer-contract .../test/fixtures/compat]
```

GREEN: 23 installer-contract + 4 compat fixtures; reference validators.

## Story 6 — Contract manifest

RED command: `go test ./test/contracts/... -run TestContractManifest -count=1 -v`
RED reason: manifest absent (demonstrated after the generator existed, by
temporarily moving manifest.json away):

```
manifest_test.go:37: manifest.json missing: open .../test/contracts/manifest.json: no such file or directory
```

GREEN: `test/contracts/manifest.json` with SHA-256 of all 88 frozen artifacts
and the frozen validation command; deterministic generator.

## Final verification commands (all exit 0)

```text
go test ./test/contracts/... -count=1 -v
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
make test
make check
make build
make clean
git diff --check 8d8fba4..HEAD
python3 test/contracts/generate_manifest.py . && go test ./test/contracts -run TestContractManifest -count=1
```

Environment note: `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001`
is required for the P03-owned sandbox spike suite (provisioned
`antinat-sandbox` identity); without it `TestBoundedActionRealCPULimitTermination`
fails closed exactly as documented by P03 QUALITY-R1 (non-blocking note).

## Repair cycle 1 (P04-FIX1) — RED observations

All RED observations were captured before the corresponding GREEN fix.

Q1 (endpoint address classes). RED command:
`go test ./test/contracts/... -count=1 -v -run 'TestProbeGoldenVectors/(arm-loopback|arm-private|arm-linklocal|arm-multicast|arm-unspecified)'`
RED reason: the reference validator accepted non-global IPv4 literals
(loopback/private/link-local/multicast/unspecified); each of the 6 new
fixtures failed with:

```
probe_test.go:67: invalid arm parsed successfully
```

GREEN: `validProbeEndpoint` now rejects non-global IPv4 via
`netip` (`IsPrivate/IsLoopback/IsLinkLocalMulticast/IsLinkLocalUnicast/
IsMulticast/IsUnspecified`); TEST-NET-2 (198.51.100.7) vectors remain valid.

Q2 (state-model manifest pinning). RED command:
`go test ./test/contracts/... -count=1 -run TestContractManifest -v`
RED reason: state-model fixtures were not listed in manifest.json after being
added to the completeness set:

```
manifest_test.go:85: frozen artifact "test/contracts/testdata/state-model/applied-forward-empty-id-invalid.json" not present in manifest
```

GREEN: `test/contracts/testdata/state-model` added to FROZEN_DIRS
(generate_manifest.py) and to both manifest_test.go functions; manifest
regenerated (136 artifacts) and byte-deterministic on re-run.

Q4c (CLI shape). RED command:
`go test ./test/contracts/... -count=1 -v -run 'TestInstallerContractGoldenVectors/(cli-unknown-short-flag|cli-token-fd-bare)'`
RED reason: `validateCLIArgs` accepted an unknown short flag and a bare
`--token-fd` with no value:

```
installer_test.go:74: invalid CLI accepted
```

GREEN: unknown short flags and bare `--token-fd`/`--token-file` (no `=value`,
no following non-flag argument) are rejected.

## Repair-cycle final verification commands (all exit 0)

```text
go test ./test/contracts/... -count=1 -v           # 10 PASS
go test ./...                                      # with ANTINAT_DEDICATED_UID/GID=12001
go test -race ./...                                # with ANTINAT_DEDICATED_UID/GID=12001
go vet ./...
make test
make check
make build
python3 test/contracts/generate_manifest.py .      # deterministic: re-run byte-identical
python3 test/contracts/validate_openapi.py
```
