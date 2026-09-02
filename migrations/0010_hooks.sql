-- AntiNAT hook schema (webhook definitions, hook secrets, durable delivery
-- queue) — migration 0010 (P16).
-- Additive only; migrations 0001-0009 are frozen and must not be rewritten.

CREATE TABLE hook_definitions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    url         TEXT NOT NULL,
    revision    INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_hook_definitions_name ON hook_definitions(name, id);

-- Secret values live ONLY in hook_secrets.ciphertext (AES-GCM at rest).
-- The plaintext value is set once at create and is never returned by the API.
CREATE TABLE hook_secrets (
    id          TEXT PRIMARY KEY,
    secret_id   TEXT NOT NULL UNIQUE,
    algorithm   TEXT NOT NULL,
    ciphertext  BLOB NOT NULL,
    key_id      TEXT NOT NULL,
    revision    INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_hook_secrets_algorithm ON hook_secrets(algorithm, id);

-- Deliveries are durable at-least-once queue items (v0.8 §8.1/§9.1):
--   state: PENDING -> IN_FLIGHT -> DELIVERED | FAILED -> (retry) | DLQED
--          DROPPED_DUE_TO_DECOMMISSION (bounded best-effort after deadline).
-- policy_json is the versioned queue policy {version,on_full,max_queue,...}.
-- payload_json carries the event payload / request-description.
CREATE TABLE hook_deliveries (
    id                    TEXT PRIMARY KEY,
    hook_id               TEXT NOT NULL REFERENCES hook_definitions(id) ON DELETE CASCADE,
    event_id              TEXT NOT NULL,
    kind                  TEXT NOT NULL DEFAULT 'lifecycle',
    state                 TEXT NOT NULL,
    attempt_count         INTEGER NOT NULL DEFAULT 0,
    max_attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at       INTEGER NOT NULL DEFAULT 0,
    policy_json           TEXT NOT NULL DEFAULT '{"version":1,"on_full":"dlq"}',
    payload_json          TEXT NOT NULL DEFAULT '',
    script_b64            TEXT NOT NULL DEFAULT '',
    secret_id             TEXT NOT NULL DEFAULT '',
    last_error            TEXT NOT NULL DEFAULT '',
    node_id               TEXT NOT NULL DEFAULT '',
    decommission_deadline INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_hook_deliveries_state ON hook_deliveries(state, next_attempt_at, id);
CREATE INDEX idx_hook_deliveries_event ON hook_deliveries(event_id, hook_id);
CREATE INDEX idx_hook_deliveries_decommission ON hook_deliveries(node_id, decommission_deadline, state);