# P14 Repair Cycle 7 — metadata-only repair

## Trigger and starting state

A fresh specification/ownership review found exactly one metadata defect. In
`.hermes/handoffs/P14.json`, `repair_cycle_5.repair_head_sha` is
`fd222543f28fb8181f9bcf0c969cb10064abda22`, but the recorded 24
`repair_cycle_5.new_or_changed_files` paths exactly match:

```text
git diff --name-only 572423b1695c3089f50f7bde12d8945aa0dcfdc1..28d8fbb3cc10de9a089f93b83f8379d358b8d4dd
```

That range includes the content commits `0670ebd445b7f63bccf5f86e1141b2f9fae11be5`
and `28d8fbb3cc10de9a089f93b83f8379d358b8d4dd`. The repair-5 head value must
therefore be `28d8fbb3cc10de9a089f93b83f8379d358b8d4dd`.

This cycle starts from the clean record tip
`e763afd776324b32db5dda3ee436564dcc1a0ab8`; the canonical implementation head
before this cycle is `428eb75657b8144ddcf49c8e3a32c19101eaf92d`, and the
canonical base remains `973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8`. The prior
quality/security review is APPROVE and remains valid. This is metadata-only:
production behavior, production tests, frozen contracts, and migrations are
out of scope.

## Exact allowed boundary

Only these two paths may be created or modified in repair cycle 7:

- `.hermes/plans/v1-beta/14-repair-7.md`
- `.hermes/handoffs/P14.json`

No production source, test, contract, migration, configuration, other plan,
other handoff, worktree, merge, rebase, cherry-pick, push, release, or
`P14-integrated` handoff may be changed or created. The plan is committed first;
the final handoff-record commit writes `P14.json` separately.

## Finding → fix → evidence

### R7-1 — repair-5 implementation/content head is stale

- **Finding:** The repair-5 file delta includes content commits through
  `28d8fbb`, while `repair_cycle_5.repair_head_sha` stops at `fd22254`.
- **Fix:** Set only `repair_cycle_5.repair_head_sha` to the exact full SHA
  `28d8fbb3cc10de9a089f93b83f8379d358b8d4dd`. Preserve repair cycles 1–6,
  including repair-5's 24-path list, except for this required correction.
  Add `repair_cycle_7` with the trigger, base, repair base, plan-commit head,
  finding map, exact changed/new plan path, generic verification, deviations,
  and known flakes. Add an explicit ownership-transfer entry for the repair-7
  plan. Update top-level canonical `head_sha`, `commits[]`, and
  `files_changed[]` only as needed to include this plan: the canonical head is
  the last pre-record plan commit, `commits[]` is the exact full-SHA output of
  `git log --format=%H base..head_sha`, and `files_changed[]` is the exact
  output of `git diff --name-only base..head_sha`. The final record commit is
  outside that canonical head.
- **Evidence:** Verify the nested repair-5 delta byte-for-byte; verify JSON;
  verify canonical head, commits, and files against Git; verify every existing
  top-level test row has `command`, `exit_code`, and `summary`; run
  `git diff --check`; and leave the worktree clean. No production tests are
  rerun because this cycle changes only metadata; the prior quality-review
  APPROVE remains the behavioral evidence.

## Required metadata verification

```text
python3 - <<'PY'
# Assert repair_cycle_5.repair_head_sha and its exact 24-path delta.
# Assert canonical head_sha, commits[], and files_changed[] equal Git output.
PY
jq -e 'all(.tests[]; has("command") and has("exit_code") and has("summary"))' .hermes/handoffs/P14.json
git diff --name-only 572423b1695c3089f50f7bde12d8945aa0dcfdc1..28d8fbb3cc10de9a089f93b83f8379d358b8d4dd
git diff --check 973cfa60ff2390fd4cbf9f9fa9f8b3afd28cd6e8..HEAD
git status --short
```
