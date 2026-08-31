# Cleanup Ledger

## Status summary

1. **Preservation: COMPLETED.**
2. **Generated `bin/` cleanup: COMPLETED with explicit user confirmation.** Four exact ignored binaries were removed; 33,278,267 bytes reclaimed.
3. **All non-allowlisted cleanup: DEFERRED.**

This ledger authorizes no branch/ref/config/code/worktree/archive cleanup. It records the exact narrow file allowlist for a later, separately executed cleanup action.

## Preservation completed

The dirty P10 base at `/root/Claude/AntiNAT/p10-mainline` was captured from base `8611d1039dc650ec6de2ef7386120cd26c1141a3` (tree `cfcd62172460e4fdc24fdc3c0812a2b31324460f`) with 19 modified tracked files and 3 untracked regression tests.

Authoritative complete archive:

- `/root/Claude/AntiNAT/preservation-archive-20260831-complete.tar.gz`
- SHA-256 `756bf22f12e34a2f25f23e4e123fba182a33a31ad42bbb234631e7823310d2cc`
- verification: `/root/Claude/AntiNAT/preservation-archive-20260831-complete.verification.txt`
- result: `OVERALL: PASS`

Preservation branch:

- `preservation/integration-v1-beta-dirty-20260831`
- commit `bcb9cdba4835e5af39d79792f3209214dd39c8cd`
- tree `459b8f947cb3d5a52fe856a9c277366eec2118ea`
- content included in P12 integration: `false`

Preservation completion is not permission to delete the live dirty worktree, the preservation branch, archives, or historical records.

## Completed exact cleanup

After explicit user confirmation, only the following ignored generated binaries were removed:

| Exact path | Bytes removed | Result |
|---|---:|---|
| `/root/Claude/AntiNAT/AntiNAT/bin/antinat-agent` | 2,406,744 | removed |
| `/root/Claude/AntiNAT/AntiNAT/bin/antinat-controller` | 2,406,752 | removed |
| `/root/Claude/AntiNAT/p12-integration/bin/antinat-agent` | 10,918,542 | removed |
| `/root/Claude/AntiNAT/p12-integration/bin/antinat-controller` | 17,546,229 | removed |

Total reclaimed from the original workspace snapshot: **33,278,267 bytes**. Before deletion, every target was revalidated as an ordinary ignored, untracked file and no running process executable resolved to any target. No recursive directory deletion was used.

Post-cleanup verification ran `make build`, which reproduced the two `p12-integration/bin` files byte-for-byte in size (28,464,771 bytes total). Those regenerated ignored outputs were then removed again under the same explicit allowlist, leaving all four paths absent in the final handoff state.

Do not expand this completed allowlist by inference. No other ignored content, worktree, archive, evidence, source, or historical file was deleted.

## Deferred set

The following remain explicitly deferred:

- `/root/Claude/AntiNAT/AntiNAT` and its preservation branch/shared Git common directory;
- `/root/Claude/AntiNAT/p10-mainline` and all 22 dirty paths;
- `/root/AntiNAT/.worktrees/t_44815fe0`, the expressly protected older seven-file P10 candidate;
- all other worktrees and worktree registrations, whether clean or dirty;
- `/root/Claude/AntiNAT/p13-udp` and branch `ai/P13-udp-dataplane` at `8f56e973722ff378881806c11e658ee8c9d96136` because P13 is reviewed but not integrated;
- all branches, refs, tags, stashes, reflogs, Git objects, and configs;
- the complete archive, earlier archive, extracted preservation package, forensic archive, original handoff archive, and all checksum/verification files;
- historical August documentation and preservation records;
- ignored `.worktrees/`, HANDOFF logs, test logs, and orchestration data;
- source code, tests, contracts, plans, configs, and any file outside the exact four-path allowlist;
- P13 integration itself (`p13_integration_authorized: false`).

## Stop conditions

Stop cleanup immediately if:

- an exact allowlisted path differs from the four names above;
- a target is tracked, a symlink, directory, or no longer an ordinary ignored generated file;
- Git status shows an unexpected tracked change before or after cleanup;
- any command would recurse beyond the named four files;
- any action would remove a worktree, modify a ref/config/stash, run `git clean`, reset dirty content, or touch an archive;
- preservation checksum/verification no longer matches;
- the operation is combined with P13 integration, code changes, or historical-document edits.

## Verification required after a later cleanup

A later authorized cleanup action should report, without changing anything else:

1. which of the four exact files existed and were removed;
2. that no other path was removed;
3. `git status --short --branch` for `/root/Claude/AntiNAT/AntiNAT` and `/root/Claude/AntiNAT/p12-integration`;
4. that the authoritative ref still resolves to `a3626376e707ffbdcdc142269dc2db6b03a2479c`;
5. that the P13 ref still resolves to `8f56e973722ff378881806c11e658ee8c9d96136` and remains not integrated;
6. that the complete archive still verifies to SHA-256 `756bf22f12e34a2f25f23e4e123fba182a33a31ad42bbb234631e7823310d2cc`.
