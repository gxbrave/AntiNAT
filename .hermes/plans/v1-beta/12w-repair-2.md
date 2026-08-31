# P12W Repair Cycle 2 — bounded fresh-review remediation

**Owner:** existing candidate branch `ai/P12W-production-wiring` in `/root/Claude/AntiNAT/p12w-wiring`.

**Base:** exact production implementation base `94e08603ca90cfa75a3a7a22b8da34016e9748d8` (the candidate implementation lineage currently ends at `37b94c92201fa96de5442d7192d571e133ca6545`; the current metadata tip is `75868d8d97f7b8c343b9c886bdde2a6293d2806d`). This is a repair plan, not an integration or approval.

## Boundary and ownership

This cycle fixes only the eight fresh-review findings supplied for P12W repair-cycle 2. It may modify only:

- `internal/agent/app.go`, `internal/agent/strategy.go`, `internal/agent/traversal_lifecycle.go`;
- the already-adapted `internal/agent/app_test.go` and `internal/agent/rollback_fence_test.go`, which are transferred P10/P12W test paths explicitly included here for fence/concurrency regression coverage;
- P12W tests `internal/agent/p12w_*.go` and `internal/agent/applied_recovery_regression_test.go`;
- `cmd/antinat-agent` tests only when required by the strategy-order behavior;
- this plan and `.hermes/handoffs/P12W.json`.

No migrations, frozen contracts/manifests, traversal libraries or STUN/UDP libraries, docs, configs, CLAUDE files, other worktrees, merge/rebase/cherry-pick, push, release, or self-approval are allowed.

## Fresh-review findings and bounded method

1. **Handoff identity and ownership.** Record exact base SHA/tree, implementation head/tree, metadata tip/tree, repair-2 commit/head metadata, complete changed-file and verification metadata. Do not describe `37b94c9` as current HEAD. The two adapted P10/P12W test paths above are explicitly owned by this repair boundary.
2. **Auto strategy correctness.** First add failing focused tests, then normalize `AutoOrder` into `a.cfg` before composition; resolve TCP auto only through the current configured order and a passed result; resolve UDP auto directly before profile load/validation; reject fixed non-direct UDP instead of coercing it; quarantine/reject profiles with no fingerprint. Preserve prior policy tests.
3. **Nil managers.** Add failing focused tests for selected direct/manual/explicit-gateway routes with missing manager pointers; return ordinary errors rather than panic, then refactor common route checks.
4. **Generation fencing.** Add deterministic blocked-acquisition tests for capability loss, fingerprint/rebuild, and composition/manager generation changes. Capture capability/composition generation before external acquisition, re-check under install lock, and detach cleanup with ownership retained on failure. Apply equivalent checks to `finishReopen`/`recover`.
5. **Same-Forward serialization.** Add a deterministic blocked concurrent apply/reopen test. Serialize one ForwardID's side effects and fence generations so duplicate resources cannot be installed and a stale operation cannot return live state for another spec.
6. **Composition snapshot and UPnP ownership.** Verify the confirmed defect at the composition root. Publish manager/detector pointers as one synchronized snapshot; avoid sharing one mutable UPnP adapter between independent owners by giving each owner an independent adapter/map (without changing traversal). Add only focused ownership/race coverage if needed.
7. **Cleanup/retry/recovery.** Add focused tests where caller cancellation follows rejection/fence and where a failed release remains owned. Use bounded detached cleanup and truthful pending state; do not claim `Acquisition.Release` retries after its `sync.Once`. Ensure cleanup completion schedules recovery retry for forwards stranded by capability loss without a new route change.
8. **Lifecycle/probe fencing and metadata.** Add deterministic deletion-window tests. Re-check live actor identity and durable deletion fence under admission ordering in `onMappingLifecycle` and `applyProbeOutcome`; use locked acquisition accessors or minimal app-facing accessors for mutable metadata. Preserve and document the accepted D5 residual replacement-token limitation; no traversal API redesign.

Every behavior change follows RED → GREEN → REFACTOR. Structural fixes must still have deterministic regression evidence where a test can express the race. Defects that cannot be reproduced at candidate HEAD remain explicitly deferred in the handoff rather than broadening this cycle.

## Required final verification

Record exact commands and exit codes in the handoff, including focused P12W tests, affected package tests/races, `go test ./...`, `go test -race ./...`, `go vet ./...`, frozen contract manifest, netns integration, Windows/Linux-arm64/Darwin cross-builds, gofmt, and `git diff --check`. Run `govulncheck` if available; if unavailable, record that honestly. Stop after coherent candidate commits and handoff for fresh independent specification, quality/security, and network review.
