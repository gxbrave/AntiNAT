# P14 Repair Cycle 3 (R3) — bounded handoff metadata repair

> This is a metadata-only repair cycle. The third-pass quality/security review
> APPROVED the P14 implementation at `5a09c37`; the third-pass spec review
> found only handoff-audit defects. No production behavior changes are allowed.

## Trigger

Fresh third-pass spec review found:

1. `.hermes/handoffs/P14.json` top-level `commits[]` used decorated short-SHA +
   subject strings rather than the exact full SHA list from the canonical
   candidate range.
2. `ownership_transfers[]` did not explicitly name every repair and transferred
   file required by the acceptance boundary (the repair specs' broad walls were
   not sufficient for the explicit-name audit).
3. The repair blocks used `repair_cycle_N_verification` rather than the generic
   `verification` field required by the handoff audit wording.

Quality/security third-pass verdict: APPROVE; no code finding is in scope for
this cycle.

## Exact boundary

Allowed files:

- `.hermes/handoffs/P14.json` — canonical metadata correction and this cycle's
  record.
- `.hermes/plans/v1-beta/14-repair-3.md` — this bounded repair specification.

Forbidden: all production source, all tests, all frozen contracts, all prior
migrations, `internal/traversal/**`, `internal/forward/udp/**`,
`test/contracts/**`, `go.mod`, `go.sum`, configs, other worktrees, and remote
push/release actions.

## Fixes

- Set top-level `head_sha` to the repair-3 metadata implementation commit
  (the commit that adds this plan; the subsequent handoff-record commit is
  excluded by the established self-referential handoff convention).
- Set top-level `commits[]` to the exact 40-character SHA output of
  `git log --format=%H <base>..<head_sha>` in the recorded order, with no
  subjects or short hashes.
- Keep `files_changed[]` equal to the exact `git diff --name-only
  <base>..<head_sha>` set; include this plan path and note that the handoff
  file is self-referential in the metadata.
- Explicitly name every P07/P08/P12W/P06 transfer and every repair test/spec
  path in `ownership_transfers[]`.
- Add a generic `verification` field to both `repair_cycle_1` and
  `repair_cycle_2` (retaining the historical named verification arrays as
  compatibility aliases), and add a `repair_cycle_3` block with exact
  metadata checks and the quality APPROVE.

## Verification

```bash
python3 - <<'PY'
# assert P14.json head_sha, exact full-SHA commits list, and files_changed set
PY
jq -e 'all(.tests[]; has("command") and has("exit_code") and has("summary"))' .hermes/handoffs/P14.json
git diff --name-only <base>..<head_sha>
git diff --check <base>..HEAD
git status --short
```

No production tests are rerun because this cycle changes only the handoff
metadata; the repair-2 full matrix and third-pass quality/security suite remain
the behavioral evidence. `govulncheck` remains unavailable as recorded in the
prior cycle.
