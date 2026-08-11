# SQLite driver feasibility spike

Question: can the Controller use a non-CGO SQLite driver with WAL, bounded lock waits, consistent backup, corruption/full-disk failure handling, and Linux/Windows builds?

Candidate: `modernc.org/sqlite v1.56.0` in the isolated nested module `driver/`. The root module remains unchanged.

Assertions:

- migrations run with WAL, `busy_timeout >= 5000ms`, foreign keys, and full synchronous mode;
- eight concurrent writers complete without lost rows;
- `VACUUM INTO` produces a consistent, integrity-checked snapshot and the file plus parent directory are synced;
- a truncated database fails the integrity gate closed;
- a deterministic `SQLITE_FULL` condition leaves the database integrity check clean;
- committed WAL rows survive a hard `SIGKILL` of the writer before any checkpoint (regression-pinned as `TestWALCommittedDataSurvivesHardKill`);
- Linux/amd64 and Windows/amd64 build with `CGO_ENABLED=0`;
- every resolved module has a hashed license record in `license-inventory.json`.

Verdict: SUPPORTED_WITH_LIMITS.

The candidate passed Linux runtime tests and non-CGO cross-builds. Windows is build-only evidence until the same database, backup, corruption, and full-disk tests run on a native Windows host. `VACUUM INTO` is the validated backup path; the lower-level online Backup API was not required for this candidate.
