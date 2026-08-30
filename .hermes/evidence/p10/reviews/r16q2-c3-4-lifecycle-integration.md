# Formal Review 4/4 — LIFECYCLE/INTEGRATION-BOUNDARY

- Candidate: C3 = commit 256c91046a00c6c18a43facf1f6ff73b576f3b23 / tree 576a3d683ee78cbacba427a6055a2a925a2d8725
- Reviewed at: metadata tip 676c6b60a8431ead4a3820a5830843526ecffdab (tree c34f55d1c62d7c9686175739ecc0d1e6621c9986)
- Reviewer: independent agent, read-only
- First attempt: FAIL at identity gate (same mandate contradiction). Resumed under corrected protocol; substantive review completed.

## 1. Verified identity line

```
Corrected protocol — all four checks verified by me, all PASS:
  (1) git rev-parse HEAD                = 676c6b60a8431ead4a3820a5830843526ecffdab  ✓
  (2) git rev-parse 256c9104^{tree}     = 576a3d683ee78cbacba427a6055a2a925a2d8725  ✓
  (3) git status --porcelain            = empty (clean)                             ✓
  (4) git diff --name-only 256c9104 HEAD = .hermes/handoffs/P10-r16q2-superseding.json
                                          .hermes/handoffs/P10.json                 ✓
        grep -v '^\.hermes/handoffs/' over that list → no output (metadata-only delta)
        git diff --stat 256c9104 -- ':!.hermes' → empty (zero implementation drift)
  256c9104 is the direct parent of HEAD; implementation bytes reviewed from the
  working tree are byte-identical to candidate C3.
```

## 2. Test results actually run (all real, no fabrication)

| Command | Result |
|---|---|
| `ANTINAT_DEDICATED_UID=12001 ANTINAT_DEDICATED_GID=12001 GOWORK=off go test -race ./internal/agent -count=3` | `ok github.com/gxbrave/AntiNAT/internal/agent 9.452s`, EXIT=0 |
| `GOWORK=off go test ./test/e2e -run TestLinuxDirectV4WalkingSkeleton -count=1` | `ok github.com/gxbrave/AntiNAT/test/e2e 1.332s`, EXIT=0 |
| Supplementary (required: the window tests live in subpackages the mandated command does not reach) `GOWORK=off go test -race ./internal/agent/localstate ./internal/agent/control ./internal/agent/reconcile -count=3` | `ok ...localstate 5.457s` / `ok ...control 13.320s` / `ok ...reconcile 11.408s`, EXIT=0 |

Per-window determinations (all code paths read at C3 bytes):

- **1a** crash after `MarkOperationApplying` (desired w/ deletions): pending flag set at `journal.go:463`; recovery gate at `journal.go:495-497` skips it → stays APPLYING. Proven by `internal/agent/localstate/journal_payload_test.go:338-394` (phase stays APPLYING, no premature C result, **no D-keyed outbox row**, fence still pending). ABSENT-only convergence + real D result: `internal/agent/app_test.go:342-398` (PRESENT sibling untouched by pointer identity, intent cleared, tombstone written, `del-recovered` queued). C NACK emitted only by `RecoverApplyingOperations` (`journal.go:525-531`) — never a fabricated D.
- **1b** crash during cleanup: tombstone-before-stop ordering `reconcile/desired.go:357-390`; intent cleared only after a successful stop and only when the tombstone exists (`localstate/forward_delete.go:207-234`). `reconcile/pending_delete_test.go:75-92` asserts both tombstone AND pending durable after a failed stop, and that the retry runs stop exactly once; `desired_test.go:294` keeps the tombstone; `pending_delete_test.go:56-70` proves no repeat stop. `dp.recover` skips fenced forwards twice over (`app.go:1767-1773`, and again in `reopen` at `app.go:1808-1813`). No tombstone is ever fabricated by recovery.
- **1c** crash after `CompleteRecoveredDeletion` before the NACK: journal is APPLYING, payload present, pending=false → redelivery takes `session.go:631-636` (converge skipped) then `RecoverApplyingOperations` NACKs C immediately. Store-level proof: `journal_payload_test.go:246-254` and the redelivery-with-pending=false shape at `260-298`. Recovery's re-fence of a completed deletion is a verified no-op (`forward_delete.go:102-115`) — no pending-row resurrection.
- **1d** legacy payload-less row: gate `(!isDeletionCommandKind(j.Kind) || j.PayloadPresent) && !j.RecoveredDeletionPending` confirmed verbatim at `journal.go:495-497`; backfill on exact redelivery at `journal.go:352-377` (zero-byte payload distinguished via `PayloadPresent`). Full lifecycle proven by `journal_payload_test.go:185-258` (skip → no fence → redelivery backfills → still APPLYING → complete → NACK, no D fabrication), `260-298`, and fail-closed identity validation at `300-325`. Non-deletion kinds still NACK immediately: `localstate/p10_r9_repair_test.go:40-70`.
- **1e** NACKED row with pending flag: branch exists and is correct (`session.go:613-629` → converge → `CompleteRecoveredDeletion` accepts NACKED per `journal.go:419` → `QueueNackedResult` `journal.go:613-631` records only `{"status":"nacked","reason"}` under C). State is reachable (`MarkOperationApplying` sets the flag at `journal.go:463`; `NackOperation`/`NackOperationWithResult` at `journal.go:580-582`/`601-602` never clear it). See MINOR on coverage.
- **Restart/reconnect**: `RequeuePending` re-envelopes the same result without repeating side effects, proven by `control/reconnect_test.go:28-120` (handler runs exactly once, session stays ONLINE); heartbeat/session-epoch fencing untouched — the `session.go` delta touches only the additive `OnRecoveredDeletion` option (`session.go:55`) and the two duplicate branches (`:613`, `:635`).
- **Shutdown**: `App.Shutdown` (`app.go:991-1050`) orders run-cancel → context-bounded client join → reconnectWG → lifecycleWG → probeMgr → `dp.closeAll` → store close; `closeAll` (`app.go:1912-1950`) closes admission, waits admissionWG, snapshots ownership, cleans actors, then joins supervisorWG and cleanupDrainWG — every stage ctx-bounded with joined errors.
- **Reserved endpoint**: `harness.go:276-296` binds the exact tuple as the OS-ownership release oracle (replacing C1's permissive echo-signature check that could false-pass against a stale listener). Both harness unit tests cover the negative and positive direction (`endpoint_release_test.go:9-38`); the caller closes it via `defer` (`walking_skeleton_test.go:253`), and defer LIFO ordering stops the restarted agent (`:260`) **before** releasing the tuple (`:253`).
- **Integration boundary**: `git diff --stat 8e39876..256c9104` touches only `internal/agent/**`, `test/e2e/**`, and `.hermes/evidence/**`. No `internal/controller/**`, `cmd/**`, or CLI path changed. The sole "decommission" token in the delta is a test's kind list (`node_decommission` as an existing non-deletion kind) — no P14 force-decommission semantics leaked. New API surface is additive agent-side only (`ClientOptions.OnRecoveredDeletion`, `ReceiveCommandWithPayloadStatus`, `CompleteRecoveredDeletion`); `ReceiveCommandWithPayload` is retained as a wrapper.

## 3. Findings

1. **MINOR** — `internal/agent/control/session.go:613-629`: window 1e (NACKED duplicate branch re-running convergence before `QueueNackedResult`) has **no test coverage**. A repo-wide search finds `OnRecoveredDeletion`/`recoveredDeletionPending` exercised only in `journal_payload_test.go` and `command_fence_test.go`, both of which drive the APPLYING branch. The state is reachable (flag set at `journal.go:463`, preserved through NACK at `journal.go:580-582`) and the branch is deterministic and correct by inspection, so under the brief's blocker rule this is a coverage gap, not a determinism defect. A test seeding NACKED+pending and redelivering would close it.
2. **MINOR** — `internal/agent/localstate/journal_payload_test.go:246-254`: window 1c is verified only at store level and by composition, not as an explicit crash-then-redeliver sequence; the session-level fall-through (`session.go:632-636`) is unexercised on the wire. Outcome is deterministic and proven at the store layer, hence MINOR.
3. **NOTE** — `internal/agent/app_test.go:342-398`: the modern (non-legacy) 1a path is verified as three composable pieces (store-level skip, app-level ABSENT-only convergence, control-level legacy redelivery at `command_fence_test.go:24-109`); no single test drives modern crash→restart→redelivery→NACK end to end.
4. **NOTE** — `test/e2e/harness/harness.go:280`: `ReserveReleasedEndpoint` returns a `net.Listener` without self-registering a `t.Cleanup`, so leak-safety rests on each caller. Both in-repo callers close correctly; future callers could leak a listener for the process lifetime. API-shape observation only.
5. **NOTE** — mandated command `go test -race ./internal/agent -count=3` compiles and runs only package `agent`; every test file named in the review scope for windows 1a-1e lives in `internal/agent/localstate` or `internal/agent/control` and is therefore **not** executed by that command. I ran those packages separately (all green) so this report's per-window claims rest on real executions; the acceptance harness should prefer `./internal/agent/...`.
6. **NOTE** — prior MINOR #2 (handoff absent from C3 tree) is resolved under the corrected protocol: the lineage file exists at HEAD and the implementation-byte equivalence is established by check 4, verified by me rather than taken from the message.

## 4. VERDICT

**PASS**

Zero BLOCKER findings against the unchanged candidate C3 tree.
