-- AntiNAT Controller core schema — migration 0001 (P06).
-- Ownership: plan 06-controller-store-auth. Frozen input: P04 state-model
-- contract + reviewed v0.8 execution plan §9.1. Later plans must add new
-- migrations; never rewrite this applied migration.
--
-- Conventions:
--   * All tables are STRICT (modernc.org/sqlite bundles SQLite >= 3.37).
--   * Timestamps are Unix seconds (INTEGER).
--   * Secret material is stored only as hashes; never plaintext.

-- One row identifying this Controller instance; used by backup manifests and
-- split-brain protection (v0.8 §6.3: v1 forbids two instances on one state).
CREATE TABLE controller_instances (
    id         TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Administrative identity for the web UI / admin API.
CREATE TABLE users (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE,
    password_hash      TEXT NOT NULL, -- argon2id encoded hash, never plaintext
    password_algorithm TEXT NOT NULL, -- e.g. "argon2id-v19"
    revision           INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
) STRICT;

-- Web admin sessions. Only the SHA-256 hash of the random session token is
-- stored; expiry and revocation are explicit columns.
CREATE TABLE web_sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL UNIQUE,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    created_at   INTEGER NOT NULL,
    ip           TEXT,
    user_agent   TEXT
) STRICT;
CREATE INDEX idx_web_sessions_user ON web_sessions(user_id);

-- Durable idempotency for creates (docs/error-codes.md §4). The key binds
-- route, principal and request hash; same key + same hash replays the stored
-- response, same key + different hash is a 409 IDEMPOTENCY_CONFLICT.
CREATE TABLE api_idempotency_keys (
    key             TEXT PRIMARY KEY,
    route           TEXT NOT NULL,
    principal       TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body   TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_idempotency_expires ON api_idempotency_keys(expires_at);

-- Durable, monotonically ordered SSE event log (v0.8 §9.1: Last-Event-ID is
-- served from this table, never from in-memory broadcast). id is the cursor.
CREATE TABLE admin_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Append-only administrative audit trail.
CREATE TABLE admin_audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_audit_actor ON admin_audit_logs(actor);
CREATE INDEX idx_audit_created ON admin_audit_logs(created_at);

-- Key/value global settings (admin password flag, retention, etc.).
CREATE TABLE global_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Stable Forward parent (frozen state-model §1). current_activation_id is
-- advanced only under a matching revision (transactional CAS). FK to
-- nodes (created in migration 0002) is enforced by SQLite.
CREATE TABLE forwards (
    id                    TEXT PRIMARY KEY,
    node_id               TEXT NOT NULL REFERENCES nodes(id),
    name                  TEXT NOT NULL,
    protocol              TEXT NOT NULL,
    current_activation_id TEXT,
    revision              INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    UNIQUE (node_id, name)
) STRICT;

-- Immutable desired-spec history per Forward; cascade with the parent.
CREATE TABLE forward_specs (
    id         TEXT PRIMARY KEY,
    forward_id TEXT NOT NULL REFERENCES forwards(id) ON DELETE CASCADE,
    revision   INTEGER NOT NULL,
    spec_json  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (forward_id, revision)
) STRICT;

-- Durable activation records per Forward; cascade with the parent.
CREATE TABLE forward_activations (
    id            TEXT PRIMARY KEY,
    forward_id    TEXT NOT NULL REFERENCES forwards(id) ON DELETE CASCADE,
    activation_id TEXT NOT NULL,
    spec_revision INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    UNIQUE (forward_id, activation_id)
) STRICT;

-- Current orthogonal state snapshot per Forward (state-model §1 axes).
CREATE TABLE forward_runtime_status (
    forward_id    TEXT PRIMARY KEY REFERENCES forwards(id) ON DELETE CASCADE,
    activation_id TEXT,
    snapshot_json TEXT NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

-- Forward deletion operations. forward_id is a LOGICAL reference: the row must
-- survive the cascade deletion of its Forward (frozen state-model §4). No
-- ON DELETE clause is attached to that column.
CREATE TABLE forward_deletion_operations (
    id               TEXT PRIMARY KEY,
    forward_id       TEXT NOT NULL,
    status           TEXT NOT NULL,
    desired_revision INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    completed_at     INTEGER
) STRICT;
CREATE INDEX idx_forward_delops_forward ON forward_deletion_operations(forward_id);
CREATE INDEX idx_forward_delops_status ON forward_deletion_operations(status);

-- Durable endpoint lifecycle events (EndpointActivated/Changed/Deactivated).
CREATE TABLE forward_endpoint_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    forward_id    TEXT NOT NULL,
    activation_id TEXT,
    event_type    TEXT NOT NULL,
    detail        TEXT,
    created_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_forward_events_forward ON forward_endpoint_events(forward_id);
