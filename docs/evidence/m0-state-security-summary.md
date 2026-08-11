# M0 state and security feasibility summary

Candidate code commit: `312999c73622798e581177c7584e48c94833d51b`

Environment: Ubuntu 24.04.3, Linux 6.8.0-136-generic, amd64, Go 1.26.5. No native Windows host was available. No router is relevant to this child.

## Classification

| Spike | Result | Production scope consequence |
|---|---|---|
| SQLite driver | `SUPPORTED_WITH_LIMITS` | Use `modernc.org/sqlite v1.56.0` as the non-CGO candidate; Linux runtime is exercised; Windows remains build-only until native fault tests pass. |
| bbolt, terminal marker, and durable control | `PASS` on Linux | M1 may consume the proven semantics after P04 freezes the state contract; native Windows crash behavior remains unpromoted. |
| Linux hook isolation | `PASS` on recorded Linux/amd64 host | Isolated JS is feasible only when every UID/env/FD/NNP/netns/mountns/empty-root/seccomp/CPU/memory gate passes. |
| Windows hook isolation | `NO_GO` | Windows falls back to webhook-only. Restricted-token/AppContainer APIs cross-build, but Job Object alone and cross-build evidence are insufficient. |
| TCP data path | `SUPPORTED_WITH_LIMITS` | Linux raw TCP copy is splice-eligible, never reported as exact runtime zero-copy; reserve a 64 KiB bidirectional fallback budget. Windows remains buffered. |
| Windows identity and Defender | `NO_GO` | Windows identity/firewall remains build-only/unsupported pending native service SID, DPAPI, protected ACL, and managed/manual Defender tests. |

Overall P03 result: `SUPPORTED_WITH_LIMITS`. The Linux SQLite/state path needed by M1 is feasible. Hook, data-path, and Windows claims are narrowed to their evidence level.

## Required P04 contract decisions

1. Freeze the SQLite candidate/version, WAL and busy-timeout pragmas, `VACUUM INTO` backup barrier, fsync expectations, integrity checks, and deterministic handling of `SQLITE_FULL`/corruption. Native Windows evidence is a separate promotion gate.
2. Freeze bbolt bucket/schema versions and a separate terminal marker whose precedence cannot be overwritten by restored state. Marker writes use temp write, file sync, rename, and parent-directory sync.
3. Freeze normal apply so candidate state never replaces LKG until apply commits. Persist delete/decommission intent before side effects; once the terminal marker exists, recovery must complete cleanup rather than restore LKG or secrets.
4. Freeze durable phases: outbox `PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC`; inbox/operation `RECEIVED -> INTENT_PERSISTED -> APPLYING -> APPLIED|NACKED`. A semantic ACK does not permit GC; only durable receipt does.
5. Persist the maximum accepted connection epoch and current session on both sides. Every inbox mutation, outbox claim, state write, side effect, and ACK must be epoch/session fenced. Old-epoch results are re-enveloped with the same semantic operation ID on the current session.
6. Same message ID plus same type/hash is a cached duplicate. Same ID plus different type/hash is a fail-closed session conflict.
7. Secret files are private-state artifacts with atomic replacement and restrictive permissions/ACLs. Backup/restore must verify hashes/permissions and enter recovery quarantine; software-only anti-rollback limitations remain explicit.
8. Linux JS minimum gates are dedicated UID, sanitized environment, no inherited descriptors, `NoNewPrivileges`, separate network namespace, empty/read-only mount view, seccomp denial of socket/connect/exec/ptrace/mount, and hard CPU/memory bounds. Failure of any gate changes capability to `UNSUPPORTED` with webhook-only fallback.
9. Windows JS remains webhook-only until the full malicious fixture matrix passes under restricted token or AppContainer with no network capability, Job Object, unwritable host paths, and no inherited handles.
10. Data-path API/UI may expose only `data_path=go_tcp_copy_splice_eligible` and `zero_copy_evidence=eligible|lab_verified|runtime_observed|not_applicable`. It must not expose `zero_copy_active`, exact `splice_bytes`, or exact buffered-fallback bytes from standard `io.Copy`.
11. Budget every bidirectional eligible connection for two 32 KiB fallback buffers. CPU/allocation/RSS values in the evidence log are observations, not pass/fail SLOs.
12. Windows promotion requires native service SID, DPAPI LocalMachine round-trip, protected key ACL, Defender managed/manual ownership, restart, upgrade, and cleanup evidence. Cross-build is never native evidence.

## Contract changes

None. P03 did not edit frozen scope or future P04 protocol/state/API contracts. This document is input to P04 rather than a silent contract revision.

## Evidence and limitations

Machine-readable records are under `test/evidence/m0/state-security/`; raw command output and environment/source digests are under its `logs/` directory. `checksums.sha256` binds the logs and records.

The P01 validator accepts one evidence JSON path per invocation. The child-plan shorthand `go run ./scripts/verify-evidence.go ./test/evidence/m0/state-security` treats the directory as a file and returns `EVIDENCE_READ_ERROR`; P03 therefore validates every JSON individually and records the directory-form incompatibility rather than modifying the unowned P01 validator.
