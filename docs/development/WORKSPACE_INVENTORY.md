# Workspace Inventory

**Snapshot date:** 2026-08-31  
**Workspace root:** `/root/Claude/AntiNAT`

This is an observational inventory, not deletion authority. Historical August documents remain historical and unchanged.

## Canonical identities

| Role | Path/ref | Identity | Status |
|---|---|---|---|
| Authoritative integrated baseline | `/root/Claude/AntiNAT/p12-integration`, `integration/P12-staging`, `integration/v1-beta` | `a3626376e707ffbdcdc142269dc2db6b03a2479c`, tree `59dec88f3249f08b76754d6d100d4ec726159f74` | Clean tracked worktree at inspection; ignored build outputs present |
| P12 candidate metadata | `/root/Claude/AntiNAT/p12-traversal`, `ai/P12-gateway-traversal` | `e254ce22d2c5c213f9120cf327277ceeaa3f8b2d` | Clean; integrated implementation already accepted on baseline |
| P13 reviewed candidate | `/root/Claude/AntiNAT/p13-udp`, `ai/P13-udp-dataplane` | `8f56e973722ff378881806c11e658ee8c9d96136`, tree `50b17468c0888bc43cd55c497ac8ca7165bd1cff` | Clean, reviewed, not integrated; `p13_integration_authorized: false` |
| Preservation branch | `/root/Claude/AntiNAT/AntiNAT`, `preservation/integration-v1-beta-dirty-20260831` | `bcb9cdba4835e5af39d79792f3209214dd39c8cd`, tree `459b8f947cb3d5a52fe856a9c277366eec2118ea` | Clean; preservation content not included in integration |
| Dirty P10 source | `/root/Claude/AntiNAT/p10-mainline` | detached `8611d1039dc650ec6de2ef7386120cd26c1141a3`, tree `cfcd62172460e4fdc24fdc3c0812a2b31324460f` | 19 modified tracked + 3 untracked; preserve/defer |

## Preservation archives

### Authoritative complete archive

- Path: `/root/Claude/AntiNAT/preservation-archive-20260831-complete.tar.gz`
- SHA-256: `756bf22f12e34a2f25f23e4e123fba182a33a31ad42bbb234631e7823310d2cc`
- Verification report: `/root/Claude/AntiNAT/preservation-archive-20260831-complete.verification.txt`
- Result: `OVERALL: PASS`
- Verified properties: outer checksum, complete internal manifest, complete-history bundle, base HEAD/tree, binary-capable patch application, exact three-file untracked overlay, exact restored porcelain-v2 dirty entries, and source stability during capture.

### Supporting/existing archives

- Extracted preservation package: `/root/Claude/AntiNAT/preservation-archive-20260831`
- Earlier archive: `/root/Claude/AntiNAT/preservation-archive-20260831.tar.gz`, SHA-256 `1c3b09df49ebbece522b24e7074bba658bde48696e20ac848840552554c57032`; valid, but superseded as the preferred artifact by the complete archive's corrected bundle verification.
- Forensic archive: `/root/Claude/AntiNAT/forensic-archive-20260826`
- Original handoff archive: `/root/Claude/AntiNAT/AntiNAT-agent-handoff-20260819T134324Z.tar.gz`, SHA-256 `14c3db2dfdd590a412de7c230d1e9e9eee3eeb7fc629fd8fe3b68b13df476df2`

Do not delete archives, checksum files, extracted inventories, or historical preservation material under the current cleanup authorization.

## Dirty P10 base captured by the complete archive

Source `/root/Claude/AntiNAT/p10-mainline` contains exactly:

- 19 modified tracked paths under `internal/controller/{agenthub,probe,store}`;
- 3 untracked regression tests:
  - `internal/controller/agenthub/takeover_fencing_regression_test.go`
  - `internal/controller/probe/lifecycle_error_regression_test.go`
  - `internal/controller/probe/negative_result_precedence_test.go`
- tracked diff summary at capture: 3,057 insertions and 509 deletions.

The archive's `RESTORE.txt` requires restoration into a new disposable destination. Do not restore over or clean the live worktree.

A separate older seven-file P10 R16Q2 candidate remains at `/root/AntiNAT/.worktrees/t_44815fe0` and is explicitly protected. It is not the same state as the later 19+3 dirty base.

## Registered worktrees

Git reported 19 registered worktrees at inspection.

### Under `/root/Claude/AntiNAT`

| Path | HEAD | State | Cleanup classification |
|---|---|---|---|
| `/root/Claude/AntiNAT/AntiNAT` | `bcb9cdb...` | clean preservation branch/shared Git common directory | Deferred; never treat as disposable |
| `/root/Claude/AntiNAT/mainline` | `adf74fa...` | clean detached | Deferred; no worktree-removal authorization |
| `/root/Claude/AntiNAT/p10-mainline` | `8611d103...` | dirty 19+3 | Deferred/protected by preservation policy |
| `/root/Claude/AntiNAT/p10-r16q2-resume` | `265ad24c...` | clean branch | Deferred; no worktree-removal authorization |
| `/root/Claude/AntiNAT/p12-integration` | `a362637...` | clean tracked state; ignored `bin/` present | Keep; authoritative baseline |
| `/root/Claude/AntiNAT/p12-traversal` | `e254ce2...` | clean branch | Deferred; no worktree-removal authorization |
| `/root/Claude/AntiNAT/p13-udp` | `8f56e97...` | clean reviewed candidate | Deferred; not integrated |

### Legacy `/root/AntiNAT/.worktrees`

Twelve registered legacy worktrees remain. Three were clean (P08, P09, P11); eight contained an untracked handoff; the old P10 R16Q2 worktree contained its expressly protected seven-file dirty candidate. All are deferred. This consolidation does not authorize removal, reset, cleaning, or ref changes for any of them.

## Cleanup status

### Preservation

`completed`

- Complete archive checksum verified.
- Disposable restore verification passed.
- Preservation branch commit exists and is clean.
- Original dirty source remained unchanged during capture.

### Exact pending allowlist

Only these four ignored generated files are approved as pending binary cleanup targets:

1. `/root/Claude/AntiNAT/AntiNAT/bin/antinat-agent`
2. `/root/Claude/AntiNAT/AntiNAT/bin/antinat-controller`
3. `/root/Claude/AntiNAT/p12-integration/bin/antinat-agent`
4. `/root/Claude/AntiNAT/p12-integration/bin/antinat-controller`

At inspection they occupied approximately 4.6 MiB and 28 MiB by directory, respectively. Their presence is ignored by Git. **Pending does not mean deleted:** all four existed at the snapshot and no deletion was performed.

### Deferred set

Everything else is deferred, including:

- all worktree directories and registrations;
- all branches, refs, tags, stashes, reflogs, and dangling objects;
- `/root/Claude/AntiNAT/p10-mainline` dirty content;
- `/root/AntiNAT/.worktrees/t_44815fe0` and every other legacy worktree;
- P13 candidate content and metadata;
- all preservation, forensic, and historical archives and checksum files;
- extracted preservation inventories;
- historical August handoff/project-plan documents;
- ignored `.worktrees/`, HANDOFF logs, test logs, and orchestration material;
- configs and repository code;
- any `bin/` directory or file not named in the four-path allowlist above.

## Evidence and integrity notes

- `git fsck --no-dangling --no-reflogs` on the authoritative repository exited 0 during consolidation.
- Existing integrated JSON records parsed successfully. P04 was the missing record and is reconstructed separately with partial-evidence labels.
- The workspace contains one recorded stash; no stash mutation is authorized.
- The old supervisor/control-plane stop documents are historical operational evidence. They do not alter current Git status and must not be used as permission to restart or delete anything.

## Machine snapshot

```yaml
snapshot_date: 2026-08-31
hostname: hermes
os: Ubuntu 24.04.3 LTS
kernel: 6.8.0-138-generic
architecture: x86_64
cpu: 13th Gen Intel(R) Core(TM) i9-13950HX
visible_cpus: 8
memory_total: 9.7 GiB
root_filesystem_size: 195 GiB
root_filesystem_free: 150 GiB
git: 2.43.0
go_binary: go1.22.2 linux/amd64
python: 3.12.3
registered_worktrees: 19
canonical_baseline: a3626376e707ffbdcdc142269dc2db6b03a2479c
p13_tip: 8f56e973722ff378881806c11e658ee8c9d96136
p13_status: reviewed_not_integrated
p13_integration_authorized: false
preservation_status: completed
bin_cleanup_status: pending
worktree_cleanup_status: deferred
archive_cleanup_status: deferred
historical_docs_status: preserved_historical
```
