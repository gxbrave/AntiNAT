# AntiNAT Protocol Contract (FROZEN)

> Status: **FROZEN at P04**. This document is a normative contract consumed by
> later Coding AIs without reinterpretation. Any change requires a versioned
> contract revision and orchestrator approval.
>
> Contract schema versions in this document:
> - Control envelope: `antinat.contracts/control-envelope/v1`
> - Enrollment transcript: `antinat.contracts/enrollment/v1`
> - Probe frame: `antinat.contracts/probe-frame/v1` (Story 2)
>
> Golden byte vectors live under `internal/protocol/testdata/**` and are
> validated by `go test ./test/contracts/... -count=1 -v`.

## 1. Scope

This contract freezes the machine-readable wire format for:

1. The normative control envelope (Controller ↔ Agent signed control frames).
2. The enrollment transcript (EnrollChallenge / EnrollRequest / EnrollResult).
3. The probe wire frames (Story 2): `ARM1` arm, `RDY1` armed, `WAN1` provider
   challenge frame, `ACK1` same-path acknowledgement, `RCT1` control receipt.
4. The strict JSON payload rules shared by all JSON payloads.

It does **not** specify a production parser implementation, server, store, or
UI. Later plans implement parsers that must accept exactly the valid golden
vectors and reject exactly the invalid vectors at the frozen rejection stage.

## 2. Conventions

- All integers are unsigned big-endian.
- All length prefixes are uint32 big-endian, in bytes.
- `||` denotes byte concatenation.
- Ed25519 signatures are 64 bytes.
- `sha256(x)` is the 32-byte SHA-256 digest.
- All lengths and caps below are normative and non-negotiable.

## 3. Normative control envelope

### 3.1 Frame layout

Every control frame is exactly:

```text
[0:4]    magic              ASCII "ANAT"
[4:5]    wire_version       uint8 = 1
[5:9]    header_len         uint32 BE
[9:13]   payload_len        uint32 BE
[13:13+h] protected_header_bytes
[13+h:13+h+p] raw_payload_bytes
[13+h+p:13+h+p+64] signature (Ed25519)
```

Normative caps:

| Constant | Value |
|---|---|
| `maxHeaderBytes` | 4096 |
| `maxPayloadBytes` | 65536 |
| `maxJSONDepth` | 16 |
| `wireVersion` | 1 |

Framing validation order (all must hold before any payload decode):

1. `len(frame) >= 13 + 64`.
2. `frame[0:4] == "ANAT"`.
3. `frame[4] == 1`.
4. `0 < header_len <= maxHeaderBytes`.
5. `payload_len <= maxPayloadBytes`.
6. `len(frame) == 13 + header_len + payload_len + 64`.

### 3.2 Protected header

The protected header is a fixed ordered list of **exactly 14** length-prefixed
fields (uint32 BE length + raw bytes). No JSON map serialization is permitted.

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `protocol_domain` | utf8 `"AntiNAT-Control-v1"` | 1..255 |
| 2 | `controller_instance_id` | raw | 16 |
| 3 | `node_id` | raw | 16 |
| 4 | `controller_key_id` | utf8 | 1..255 |
| 5 | `agent_credential_version` | uint32 BE | 4 |
| 6 | `connection_epoch` | uint64 BE | 8 |
| 7 | `session_id` | utf8 | 1..255 |
| 8 | `direction` | 1 byte: `0x01` C2A, `0x02` A2C | 1 |
| 9 | `sequence` | uint64 BE | 8 |
| 10 | `message_id` | raw | 16 |
| 11 | `message_type` | utf8 | 1..255 |
| 12 | `schema_version` | uint32 BE | 4 |
| 13 | `payload_length` | uint64 BE | 8 |
| 14 | `payload_sha256` | raw | 32 |

Header validation order:

1. All 14 fields must be present; the header must contain no trailing bytes.
2. Fixed-size fields must have their exact sizes.
3. `protocol_domain == "AntiNAT-Control-v1"`.
4. `payload_length == payload_len` (frame field).
5. `sha256(payload) == payload_sha256`.
6. `direction` is `0x01` or `0x02`.
7. `agent_credential_version != 0`.

### 3.3 Signature

```text
signature_input = protocol_domain_bytes || protected_header_bytes || payload_sha256_bytes
signature       = Ed25519.Sign(peer_private_key, signature_input)
```

Verification uses the pinned peer public key (Controller verifies with the
Agent's key, Agent verifies with the Controller's key). A wrong key, a stale
epoch/session, a tampered header, or a tampered payload hash all fail closed
before any payload decode.

### 3.4 Strict JSON payload rules

JSON payloads (when present) are validated with a strict decoder before any
semantic use:

1. The payload must be a single JSON object (no arrays at top level, no
   trailing garbage).
2. Duplicate keys are rejected.
3. Unknown fields are rejected against the per-message schema.
4. Nesting depth is bounded at 16.
5. All numbers must be finite integers within the int64 range; fractional and
   exponential forms are rejected.
6. Payload size is bounded by `maxPayloadBytes`.

### 3.5 Message dedup semantics

- Same `message_id` + same `message_type` + same payload hash: cached result
  returned.
- Same `message_id` + different type or hash: fail-closed session conflict,
  audited, connection treated as compromised/stale.

### 3.6 Normative message types

| `message_type` | Direction | Purpose |
|---|---|---|
| `desired` | C2A | Desired Forward/node state (JSON payload) |
| `desired_result` | A2C | Result of applying desired state |
| `forward_delete` | C2A | Explicit deletion command (carries `deletion_operation_id`) |
| `forward_delete_ack` | A2C | Acknowledgment of deletion |
| `node_decommission` | C2A | Node decommission command |
| `node_decommission_ack` | A2C | Decommission acknowledgment |
| `message_receipt` | A2C | Durable receipt for an outbox message |
| `operation_complete` | A2C | Operation completion result |
| `probe_arm` | C2A | Probe arming (never carries the challenge) |
| `probe_armed` | A2C | Durable probe armed response |
| `probe_ingress_receipt` | A2C | Signed control receipt for a provider frame |
| `probe_result` | A2C | Probe outcome result |
| `key_rotation_prepare` / `key_rotation_ack` / `key_rotation_commit` | both | Key rotation FSM |
| `restore_reconcile` / `restore_result` | both | Restore reconciliation |
| `heartbeat` | A2C | Heartbeat/status/traffic |
| `status` | A2C | Status snapshot |

## 4. Enrollment transcript

The enrollment transcript is three signed messages. All use the domain
`"AntiNAT-Enroll-v1"` and canonical length-prefixed field encoding (uint32 BE
length + raw bytes), never JSON maps.

### 4.1 EnrollChallenge (Controller → Agent, signed by pinned Controller key)

Fields (in order):

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `controller_instance_id` | raw | 16 |
| 2 | `controller_key_id` | utf8 | 1..255 |
| 3 | `node_id` | raw | 16 |
| 4 | `server_nonce` | raw | 32 |
| 5 | `protocol_versions` | utf8, `"1"` | 1..255 |
| 6 | `expiry_unix` | uint64 BE | 8 |

Signature input: `"AntiNAT-Enroll-v1" || canonical_fields`.

### 4.2 EnrollRequest (Agent → Controller, signed by the new Agent key)

The signature is the possession proof. Fields (in order):

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `challenge_hash` | sha256 of the canonical EnrollChallenge | 32 |
| 2 | `agent_nonce` | raw | 32 |
| 3 | `agent_public_key` | Ed25519 public key | 32 |
| 4 | `agent_credential_version` | uint32 BE, non-zero | 4 |
| 5 | `token` | utf8, 1..256 bytes | 1..256 |
| 6 | `capability_hash` | sha256 | 32 |

Signature input: `"AntiNAT-Enroll-v1" || canonical_fields`, verified against
`agent_public_key` (self-possessed key).

Validation:

1. The `challenge_hash` must equal the server-issued challenge hash.
2. Token length must be within 1..256.
3. `agent_credential_version` must be non-zero.
4. Signature must verify against the presented `agent_public_key`.

### 4.3 EnrollResult (Controller → Agent, signed by Controller signing key)

Fields (in order):

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `controller_instance_id` | raw | 16 |
| 2 | `controller_key_id` | utf8 | 1..255 |
| 3 | `node_id` | raw | 16 |
| 4 | `agent_public_key_hash` | sha256 of agent public key | 32 |
| 5 | `agent_credential_version` | uint32 BE, non-zero | 4 |
| 6 | `enrollment_result_id` | raw | 16 |
| 7 | `expiry_unix` | uint64 BE | 8 |

Signature input: `"AntiNAT-Enroll-v1" || canonical_fields`.

### 4.4 Enrollment rules

1. Token consumption, credential binding, and enrollment result ID are
   committed in a single SQLite transaction.
2. If the EnrollResult response is lost, the same node + same key + valid
   possession proof returns the original binding result (idempotent).
3. A different key on a registered node fails uniformly and is audited;
   ordinary enrollment tokens cannot rebind a registered node's key.
4. Tokens never appear in generated commands, shell history, argv, env,
   service units, config, or logs. Interactive installs read tokens from a
   hidden TTY prompt; non-interactive installs accept only `--token-fd` or a
   strict-ACL `--token-file`, deleted after consumption.

## 5. Fixture schema summary

All fixture files are JSON and carry a `schema` field:

- Control envelope: `antinat.contracts/control-envelope/v1` with `frame_hex`,
  `verifier` (`agent`|`controller`), `public_key_hex`, `expect`
  (`valid`|`invalid`), `reject_stage`
  (`framing`|`header`|`consistency`|`signature`|`payload_json`), and header
  expectations.
- Enrollment: `antinat.contracts/enrollment/v1` with `kind`
  (`challenge`|`request`|`result`), `message_hex`, `expect`, `reject_reason`
  (`malformed`|`domain`|`challenge`|`signature`), plus semantic expectations.

Test keys are deterministic, published TEST-ONLY fixture keys (seeds `0x11`,
`0x22`, `0x33`); they are never real credentials.

## 6. Versioning and change control

- Frozen at P04 commit. The SHA-256 of this file and every fixture is recorded
  in `test/contracts/manifest.json`.
- A contract revision requires a proposal, orchestrator approval, and a new
  schema version (`/v2`); old vectors remain valid for their schema version.
