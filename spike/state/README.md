# bbolt, terminal-marker, and durable-control feasibility spike

Question: can the Agent preserve last-known-good state across partial apply, fence stale sessions durably, and make delete/decommission non-resurrecting across every control phase?

Candidate: `go.etcd.io/bbolt v1.5.0` plus a separate atomic terminal marker written as temp-file write, file sync, rename, and parent-directory sync.

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
- the prototype passes the race detector and cross-compiles its tests for Windows/amd64.

Verdict: PASS for the Linux state semantics exercised here. The Windows cross-build is not native filesystem crash evidence. P04 must freeze explicit bucket/version layouts, terminal-marker precedence, operation phases, recovery quarantine, and a native-platform fault matrix before production implementation.
