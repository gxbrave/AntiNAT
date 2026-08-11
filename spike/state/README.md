# bbolt, terminal-marker, and durable-control feasibility spike

Question: can the Agent preserve last-known-good state across partial apply, fence stale sessions durably, make delete/decommission non-resurrecting across every control phase, and exchange domain-separated signed commands on both sides?

Candidate: `go.etcd.io/bbolt v1.5.0` plus a separate atomic terminal marker written as temp-file write, file sync, rename, and parent-directory sync, and an Ed25519 signed envelope for two-sided Controller/Agent control traffic.

Assertions:

- an interrupted normal apply leaves the prior LKG untouched;
- abrupt process exit at intent, marker, side effect, result, semantic ACK, and durable receipt is recovered deterministically;
- before the terminal marker, old LKG remains retryable; from the marker onward, LKG and secrets never resurrect;
- a terminal ACK remains queued until durable receipt, including after recovery;
- corrupt bbolt input fails closed;
- key files are atomically replaced with mode `0600` under a private state directory;
- persisted epoch/session fencing rejects stale inbound commands, stale outbound claims, and old-epoch ACKs after restart;
- identical message IDs deduplicate, while conflicting type/hash reuse fails closed;
- semantic results are re-enveloped for the current session and garbage-collected only after receipt;
- the durable outbox FSM `PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC` is enforced with exact-predecessor (CAS-like) transitions: premature receipt GC, double claim, claim-after-ACK, ACK-without-SENT, cross-session receipt GC, stale-writer overwrite, and duplicate receipt all fail closed; receipt is bound to the current epoch/session and to a `SEMANTIC_ACKED` row, and a receipted operation cannot resurrect;
- distinct Controller and Agent stores verify domain-separated Ed25519 signatures over a canonical binary protected header before any inbox/outbox mutation; stale signed commands are rejected on both sides, and tampered, wrong-key, wrong-direction, and replayed envelopes fail closed;
- the prototype passes the race detector and cross-compiles its tests for Windows/amd64.

Verdict: PASS for the Linux state semantics exercised here. The Windows cross-build is not native filesystem crash evidence. P04 must freeze explicit bucket/version layouts, terminal-marker precedence, operation phases, recovery quarantine, the signed envelope framing/domain, and a native-platform fault matrix before production implementation.
