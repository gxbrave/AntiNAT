-- AntiNAT lifecycle schema — migration 0008 (P14).
-- Ownership: plan 14-lifecycle-rotation-recovery. Extends the controller-side
-- phase-journal rows the frozen state-model §7.3/§7.4/§8.3 and protocol.md
-- require: the 0002 node_cleanup_tombstones table gains the P14 columns (force
-- delete keeps the old key out; allowed key hashes / credential versions across
-- a rotation overlap; whether the remote cleanup was ever confirmed), and new
-- key rotation operations + restore reconciliation tables are added.
--
-- The 0002 cleanup tombstone is the frozen-declared table shape; 0008 only
-- appends columns and a unique index (SQLite has no portable ADD CONSTRAINT).
-- Migrations 0001-0007 are never edited.

-- Node cleanup tombstones: extend the 0002 table with the force-delete facts.
ALTER TABLE node_cleanup_tombstones ADD COLUMN operation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE node_cleanup_tombstones ADD COLUMN force INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_cleanup_tombstones ADD COLUMN remote_cleanup_confirmed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_cleanup_tombstones ADD COLUMN allowed_key_hashes TEXT NOT NULL DEFAULT '[]';
ALTER TABLE node_cleanup_tombstones ADD COLUMN credential_versions TEXT NOT NULL DEFAULT '[]';
ALTER TABLE node_cleanup_tombstones ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;

-- One tombstone per node: the upsert path in the store relies on node_id being
-- unique. The 0002 index stays; this unique index is the conflict target.
CREATE UNIQUE INDEX idx_cleanup_tombstones_node_unique
    ON node_cleanup_tombstones(node_id);

-- Restore quarantine: the 0002 nodes table gains a durable quarantine flag so
-- RESTORE_RECONCILIATION can suspend automatic desired/delete/rotation
-- dispatch per node until an administrator reauthorizes it.
ALTER TABLE nodes ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0;

-- One key-rotation operation per durable FSM instance. The certificate is
-- signed by the OLD key; the phase follows PREPARED -> ANNOUNCED -> ACKED ->
-- ACTIVE -> RETIRED. An offline Agent that never ACKed blocks normal retire;
-- force retire requires manual re-pin/re-enroll.
CREATE TABLE IF NOT EXISTS key_rotation_operations (
    id                TEXT PRIMARY KEY,
    scope             TEXT NOT NULL,   -- 'controller' | 'agent' | 'master' | 'hook' | 'probe'
    old_key_id        TEXT NOT NULL,
    old_key_generation INTEGER NOT NULL,
    new_key_id        TEXT NOT NULL,
    new_public_key    TEXT NOT NULL,   -- hex public key (never private material)
    new_generation    INTEGER NOT NULL,
    phase             TEXT NOT NULL,   -- PREPARED | ANNOUNCED | ACKED | ACTIVE | RETIRED
    not_before_unix   INTEGER NOT NULL,
    overlap_deadline_unix INTEGER NOT NULL,
    certificate       TEXT NOT NULL DEFAULT '',   -- JSON rotation certificate
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_key_rotation_ops_phase
    ON key_rotation_operations(phase, updated_at, id);

-- One restore/recovery operation: the durable record of a Controller restore
-- entering RESTORE_RECONCILIATION. Nodes are quarantined (no automatic
-- desired/delete/rotation dispatch) until an administrator reauthorizes them.
CREATE TABLE IF NOT EXISTS restore_operations (
    id                  TEXT PRIMARY KEY,
    controller_instance TEXT NOT NULL,
    manifest_sha256     TEXT NOT NULL,
    schema_version      INTEGER NOT NULL,
    phase               TEXT NOT NULL,  -- RESTORE_RECONCILIATION | RECONCILING | AUTHORIZED
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_restore_ops_phase
    ON restore_operations(phase, created_at, id);