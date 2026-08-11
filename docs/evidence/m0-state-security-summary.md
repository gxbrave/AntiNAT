# M0 state and security feasibility summary

Candidate code commit: `689ca5788321ba80bd9b108230d89024dccbfecd` (P03 repair cycle 1; replaces `312999c`)

Environment: Ubuntu 24.04.3, Linux 6.8.0-136-generic, amd64, Go 1.26.5. A dedicated sandbox identity `antinat-sandbox` (UID/GID 12001) was provisioned on the evidence host; the recorded Linux hook-isolation gates use it. No native Windows host was available. No router is relevant to this child.

## Classification

| Spike | Result | Production scope consequence |
|---|---|---|
| SQLite driver | `SUPPORTED_WITH_LIMITS` | Use `modernc.org/sqlite v1.56.0` as the non-CGO candidate; Linux runtime is exercised (including a regression-pinned WAL hard-kill durability test); Windows remains build-only until native fault tests pass. |
| bbolt, terminal marker, and durable control | `PASS` on Linux | M1 may consume the proven semantics after P04 freezes the state contract; native Windows crash behavior remains unpromoted. |
| Linux hook isolation | `PASS` on recorded Linux/amd64 host | Isolated JS is feasible only when every UID/env/FD/NNP/netns/mountns/empty-root/seccomp/CPU/memory/output gate passes, with a provisioned unique non-nobody service UID/GID (never the shared nobody identity). |
| Windows hook isolation | `NO_GO` | Windows falls back to webhook-only. Restricted-token/AppContainer APIs cross-build, but Job Object alone and cross-build evidence are insufficient. |
| TCP data path | `SUPPORTED_WITH_LIMITS` | Linux raw TCP copy is splice-eligible, never reported as exact runtime zero-copy; reserve a 64 KiB bidirectional fallback budget. Windows remains buffered. |
| Windows identity and Defender | `NO_GO` | Windows identity/firewall remains build-only/unsupported pending native service SID, DPAPI, protected ACL, and managed/manual Defender tests; the classification fails closed while Defender ownership is unvalidated. |

Overall P03 result: `SUPPORTED_WITH_LIMITS`. The Linux SQLite/state path needed by M1 is feasible. Hook, data-path, and Windows claims are narrowed to their evidence level.

## P03 repair cycle 1 (task t_e3855607)

The reviewed candidate at `dae3858` was repaired against QUALITY Q1-Q4 and SPEC F1-F2. Per-Story RED evidence (including the raw failing commands/outputs) is in `test/evidence/m0/state-security/logs/tdd-red.txt`:

- Q1/F1 Story 3: the durable outbox FSM `PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC` is now enforced with exact-predecessor transitions; receipts are epoch/session-bound, require `SEMANTIC_ACKED`, and are tombstoned so duplicate receipts and receipted-operation resurrection fail closed. Eight adversarial tests pin the bypasses.
- Q4/F2 Story 3: a two-sided Ed25519 signed-command prototype now exists (`spike/state/prototype/signed.go`) with distinct Controller/Agent stores, a canonical binary protected header, and stale/tampered/wrong-key/wrong-direction/replay rejection on both sides.
- Q2 Story 4: the `dedicated_uid` gate now requires a provisioned, unique, non-nobody UID/GID (`ANTINAT_DEDICATED_UID`/`ANTINAT_DEDICATED_GID`); the shared nobody identity 65534 and missing/non-unique provisions fail closed. The evidence host provisioned `antinat-sandbox` UID/GID 12001.
- Q3 Story 4: child output is capped at 64 KiB, descendants are bounded by `RLIMIT_NPROC`, a private process group, and seccomp denial of fork/vfork; the CPU gate accepts only the limit-specific SIGXCPU observable (never a generic SIGKILL) and the allocation gate only the runtime OOM message; a real bounded-path test exercises the end-to-end SIGXCPU proof.
- F1: per-Story RED evidence added for SQLite (WAL sabotage), control (FSM bypasses), signed commands (absent feature), sandbox (identity + resource gates), evidence classification (enum sabotage), and the Windows-identity sub-spike (Defender gating), plus the raw `tdd-red.txt` artifact.

## Required P04 contract decisions

1. Freeze the SQLite candidate/version, WAL and busy-timeout pragmas, `VACUUM INTO` backup barrier, fsync expectations, integrity checks, and deterministic handling of `SQLITE_FULL`/corruption. Native Windows evidence is a separate promotion gate.
2. Freeze bbolt bucket/schema versions and a separate terminal marker whose precedence cannot be overwritten by restored state. Marker writes use temp write, file sync, rename, and parent-directory sync.
3. Freeze normal apply so candidate state never replaces LKG until apply commits. Persist delete/decommission intent before side effects; once the terminal marker exists, recovery must complete cleanup rather than restore LKG or secrets.
4. Freeze durable phases: outbox `PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC`; inbox/operation `RECEIVED -> INTENT_PERSISTED -> APPLYING -> APPLIED|NACKED`. A semantic ACK does not permit GC; only durable receipt does. Transitions require their exact predecessor and the receipt is epoch/session/result bound with a durable tombstone.
5. Persist the maximum accepted connection epoch and current session on both sides. Every inbox mutation, outbox claim, state write, side effect, and ACK must be epoch/session fenced. Old-epoch results are re-enveloped with the same semantic operation ID on the current session. Control traffic uses a canonical binary protected header with a domain-separated Ed25519 signature verified on both sides before any mutation.
6. Same message ID plus same type/hash is a cached duplicate. Same ID plus different type/hash is a fail-closed session conflict.
7. Secret files are private-state artifacts with atomic replacement and restrictive permissions/ACLs. Backup/restore must verify hashes/permissions and enter recovery quarantine; software-only anti-rollback limitations remain explicit.
8. Linux JS minimum gates are a provisioned unique non-nobody dedicated UID/GID, sanitized environment, no inherited descriptors, `NoNewPrivileges`, separate network namespace, empty/read-only mount view, seccomp denial of socket/connect/exec/ptrace/mount/fork/vfork, bounded process count, capped child output, and hard CPU/memory bounds proven by limit-specific observables. Failure of any gate changes capability to `UNSUPPORTED` with webhook-only fallback.
9. Windows JS remains webhook-only until the full malicious fixture matrix passes under restricted token or AppContainer with no network capability, Job Object, unwritable host paths, and no inherited handles.
10. Data-path API/UI may expose only `data_path=go_tcp_copy_splice_eligible` and `zero_copy_evidence=eligible|lab_verified|runtime_observed|not_applicable`. It must not expose `zero_copy_active`, exact `splice_bytes`, or exact buffered-fallback bytes from standard `io.Copy`.
11. Budget every bidirectional eligible connection for two 32 KiB fallback buffers. CPU/allocation/RSS values in the evidence log are observations, not pass/fail SLOs.
12. Windows promotion requires native service SID, DPAPI LocalMachine round-trip, protected key ACL, Defender managed/manual ownership, restart, upgrade, and cleanup evidence. Cross-build is never native evidence.

## Contract changes

None. P03 did not edit frozen scope or future P04 protocol/state/API contracts. This document is input to P04 rather than a silent contract revision.

## Evidence and limitations

Machine-readable records are under `test/evidence/m0/state-security/`; raw command output and environment/source digests are under its `logs/` directory. `checksums.sha256` binds the logs and records. The raw per-Story TDD RED evidence is in `logs/tdd-red.txt`.

The P01 validator accepts one evidence JSON path per invocation. The child-plan shorthand `go run ./scripts/verify-evidence.go ./test/evidence/m0/state-security` treats the directory as a file and returns `EVIDENCE_READ_ERROR`; P03 therefore validates every JSON individually and records the directory-form incompatibility rather than modifying the unowned P01 validator.
