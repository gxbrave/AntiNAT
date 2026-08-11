# P05 per-Story TDD RED evidence

All RED observations were captured before the GREEN implementation for each
story. Commands are the exact focused invocations; failures are the expected
feature-absent or bug-present reasons.

## Story 1 — Fixed frame parser (envelope / enrollment / probe)

RED command: `go test ./internal/protocol/ -count=1`
RED reason: the protocol package had no envelope symbols (feature absent):

```
internal/protocol/envelope_test.go:15:19: undefined: ProtectedHeader
internal/protocol/envelope_test.go:120:21: undefined: ParseEnvelope
internal/protocol/envelope_test.go:124:14: undefined: StageOK
...
internal/security/framecrypto/framecrypto_test.go:15:14: undefined: Sign
```

GREEN: bounded envelope parser/encoder over the exact protected bytes,
enrollment transcript codecs, probe wire codecs + agent state machine, and
the framecrypto primitives. Every malformed length/domain/hash/signature
vector fails at the frozen stage before any payload decode.

## Story 1 VERIFY — frozen vectors and bit-flip table

RED command: `go test ./internal/protocol/ -run 'Golden' -count=1`
RED reason: undefined `ValidateStrictJSON` (Story 2 dependency) — the golden
gate could not compile until the strict JSON decoder existed:

```
internal/protocol/golden_test.go:175:16: undefined: ValidateStrictJSON
```

GREEN: golden gate over all frozen `internal/protocol/testdata/**` vectors
(19 control-envelope, 11 enrollment, 32 probe-frame) plus the full bit-flip
table; every valid vector parses, every invalid vector rejects at the frozen
stage, and no single-bit mutation of a valid vector ever reaches payload
decode. 66 fixture subtests, 0 failures.

## Story 2 — Strict payload decoding

RED command: `go test ./internal/protocol/ -run TestStrictJSON -count=1`
RED reason: undefined symbols (feature absent), then a behavioral gap on
trailing garbage after the strict decoder existed:

```
strictjson_test.go:59: got code "malformed", want "trailing_garbage"
  (err=protocol: strict json malformed: protocol: malformed JSON)
```

GREEN: strict bounded decoder with stable machine-readable codes and
errors.Is-compatible sentinels; post-object content (even syntactically
invalid bytes) reports `trailing_garbage`.

## Story 3 — Domain types and validation

RED command: `go test ./internal/protocol/ -run 'Test(Activation|Publication|Forward|FSM|ProbeOutcome|Capability)' -count=1`
RED reason: undefined domain symbols (feature absent):

```
internal/protocol/domain_test.go:16:8: undefined: ValidAxisValue
internal/protocol/domain_test.go:79:7: undefined: ActivationStates
...
```

GREEN: DesiredState, ForwardSpec/ForwardActivation, AppliedForwardState,
activation-state axes with frozen enums, publication truth invariants,
durable control FSM tables, operation kinds, probe outcomes, and capability
results. Invalid state enums, port constraints, v6 Forwards, private
published candidates, and impossible layer relations all fail.

## Story 4 — Endpoint/network classes

RED command: `go test ./internal/protocol/ -run 'Test(Classify|Endpoint|IsGlobal)' -count=1`
RED reason: undefined classification symbols (feature absent):

```
internal/protocol/endpoint_test.go:24:9: undefined: EndpointClass
internal/protocol/endpoint_test.go:26:15: undefined: ClassUnspecified
...
```

GREEN: explicit table-based `ClassifyIP` (RFC1918, CGNAT 100.64/10,
loopback, link-local, benchmark 198.18/15, documentation TEST-NET,
multicast, reserved, unspecified, IPv4-mapped IPv6, global unicast) with
`IsGlobalEndpoint`/`ValidateEndpoint` backing the probe-arm and
published-candidate rules; probe/domain validators refactored onto the
single classifier.

## Story 5 — Config parsing

RED command: `go test ./internal/config/ -count=1`
RED reason: undefined config symbols (feature absent):

```
internal/config/config_test.go:17:15: undefined: ParseControllerConfig
internal/config/config_test.go:166:16: undefined: LoadAgentConfig
...
```

GREEN: strict JSON Controller/Agent configs; unknown keys, duplicate keys,
insecure public-enrollment default (fail closed), malformed http(s)/stun
URLs, and out-of-bounds ports/log levels rejected; token files must be mode
0600; Redacted()/String() never log token material.

## Story 6 — Fuzz/regression

RED command: `go test ./internal/protocol/ -run 'TestEnrollmentShortFieldNoPanic' -count=1`
RED reason: genuine panic — fixed-width big-endian reads happened before
their length checks:

```
panic: runtime error: index out of range [7] with length 3 [recovered, repanicked]
encoding/binary.bigEndian.Uint64(...)
protocol.ParseEnrollChallenge(...) internal/protocol/enrollment.go:126
```

GREEN: enrollment parsers validate every fixed width before any big-endian
read or copy; regression tests pin short-field rejection for enrollment,
envelope, and probe paths; bounded-allocation tests; fuzz targets for frame,
JSON payload, probe, endpoint, and config.

Fuzz verification (each target fuzzed 30s, all PASS, no panics/crashes):

```
go test ./internal/protocol -run '^$' -fuzz='^FuzzParseEnvelope$'   -fuzztime=30s   # 6.4M execs
go test ./internal/protocol -run '^$' -fuzz='^FuzzParseEnrollment$' -fuzztime=30s   # 8.1M execs
go test ./internal/protocol -run '^$' -fuzz='^FuzzParseProbe$'      -fuzztime=30s   # 7.0M execs
go test ./internal/protocol -run '^$' -fuzz='^FuzzStrictJSON$'      -fuzztime=30s   # 0.7M execs
go test ./internal/protocol -run '^$' -fuzz='^FuzzClassifyEndpoint$' -fuzztime=30s  # 6.9M execs
go test ./internal/config   -run '^$' -fuzz='^FuzzParseConfigs$'    -fuzztime=30s   # 0.8M execs
```

Note: the plan's literal `-fuzz=Fuzz` matches five targets in one package;
the Go toolchain refuses to fuzz when the regex matches more than one fuzz
test, so the equivalent per-target invocations above are used (documented in
the handoff).
