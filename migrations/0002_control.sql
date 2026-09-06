-- AntiNAT Controller control-plane schema — migration 0002 (P06).
-- Ownership: plan 06-controller-store-auth. Consumed by P08 (enrollment /
-- control channel) and later plans via new migrations only.
--
-- Conventions mirror migration 0001: STRICT tables, Unix-second timestamps,
-- secret material stored only as hashes.

-- Agent control nodes. current_connection_epoch/current_session_id are the
-- two-way connection epoch fencing columns (frozen §6.3); they are mutated
-- only under transactional CAS.
CREATE TABLE nodes (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL UNIQUE,
    current_connection_epoch  INTEGER NOT NULL DEFAULT 0,
    current_session_id        TEXT,
    control_state             TEXT NOT NULL DEFAULT 'OFFLINE',
    revision                  INTEGER NOT NULL DEFAULT 0,
    created_at                INTEGER NOT NULL,
    updated_at                INTEGER NOT NULL
) STRICT;

-- One-time enrollment tokens; only the token hash is stored.
CREATE TABLE node_enrollment_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    node_id     TEXT REFERENCES nodes(id) ON DELETE SET NULL,
    status      TEXT NOT NULL,
    expires_at  INTEGER,
    created_at  INTEGER NOT NULL,
    consumed_at INTEGER
) STRICT;
CREATE INDEX idx_enroll_tokens_status ON node_enrollment_tokens(status);

-- Bound Agent credentials (public key hash + credential version).
CREATE TABLE node_credentials (
    id                 TEXT PRIMARY KEY,
    node_id            TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    key_type           TEXT NOT NULL,
    public_key_hash    TEXT NOT NULL,
    credential_version INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    UNIQUE (node_id, credential_version)
) STRICT;

-- Node deletion/decommission operations. node_id is a LOGICAL reference: the
-- row survives the node row (frozen §4: deletion rows are never cascade
-- deleted). mode is 'normal' or 'force'.
CREATE TABLE node_deletion_operations (
    id           TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    status       TEXT NOT NULL,
    mode         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    completed_at INTEGER
) STRICT;
CREATE INDEX idx_node_delops_node ON node_deletion_operations(node_id);
CREATE INDEX idx_node_delops_status ON node_deletion_operations(status);

-- Cleanup tombstones for decommissioned nodes; never cascade-deleted.
CREATE TABLE node_cleanup_tombstones (
    id         TEXT PRIMARY KEY,
    node_id    TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_cleanup_tombstones_node ON node_cleanup_tombstones(node_id);

-- Durable control outbox (frozen state-model §3.1). Stores the SEMANTIC
-- payload, never a signed frame for an old session (v0.8 §3.5); the same
-- operation/message ID is re-enveloped/re-signed on reconnect.
CREATE TABLE control_outbox (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id     TEXT NOT NULL,
    message_type     TEXT NOT NULL,
    node_id          TEXT NOT NULL,
    semantic_payload TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'PENDING',
    attempt_count    INTEGER NOT NULL DEFAULT 0,
    session_id       TEXT,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    UNIQUE (operation_id, message_type)
) STRICT;
CREATE INDEX idx_outbox_state ON control_outbox(state);
CREATE INDEX idx_outbox_node ON control_outbox(node_id);

-- Durable control inbox (frozen state-model §3.2 FSM).
CREATE TABLE control_inbox (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id       TEXT NOT NULL UNIQUE,
    node_id          TEXT NOT NULL,
    message_type     TEXT NOT NULL,
    semantic_payload TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'RECEIVED',
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_inbox_node ON control_inbox(node_id);
CREATE INDEX idx_inbox_state ON control_inbox(state);
