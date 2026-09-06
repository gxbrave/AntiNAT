-- AntiNAT hook schema (webhook definitions, hook secrets, durable delivery
-- queue) — migration 0010 (P16).
-- Additive only; migrations 0001-0009 are frozen and must not be rewritten.

CREATE TABLE hook_definitions (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    kind              TEXT NOT NULL,
    url               TEXT NOT NULL,
    -- Per-hook signing param allowlist (JSON array of allowed param keys).
    -- Query-placement signing FAILS CLOSED unless a key is allowlisted; the
    -- allowlist is manipulated only via the internal SetHookParamsAllowlist API
    -- (never part of the frozen OpenAPI surface).
    allow_params_json TEXT NOT NULL DEFAULT '[]',
    revision          INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_hook_definitions_name ON hook_definitions(name, id);

-- Secret values live ONLY in hook_secrets.ciphertext (AES-GCM at rest).
-- The plaintext value is set once at create and is never returned by the API.
-- signature_budget is the durable, hard cap on the total number of signatures
-- this secret can ever issue (0 = no signing allowed, fail closed); the broker
-- reserves one unit per issued signature so the secret is never a signing
-- oracle. signature_issued is the running counter.
CREATE TABLE hook_secrets (
    id                TEXT PRIMARY KEY,
    secret_id         TEXT NOT NULL UNIQUE,
    algorithm         TEXT NOT NULL,
    ciphertext        BLOB NOT NULL,
    key_id            TEXT NOT NULL,
    signature_budget  INTEGER NOT NULL DEFAULT 0,
    signature_issued  INTEGER NOT NULL DEFAULT 0,
    revision          INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_hook_secrets_algorithm ON hook_secrets(algorithm, id);

-- Internal secret-to-hook binding (P1-2): a secret may only sign deliveries
-- for a hook it is explicitly bound to. The broker refuses Sign for an unbound
-- (hook_id, secret_id) pair (ErrSecretNotBoundToHook, fail closed). The binding
-- is internal to internal/hook and wired by P17; it is never part of the
-- frozen API response schemas.
CREATE TABLE hook_secret_bindings (
    hook_id    TEXT NOT NULL REFERENCES hook_definitions(id) ON DELETE CASCADE,
    secret_id  TEXT NOT NULL REFERENCES hook_secrets(secret_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (hook_id, secret_id)
) STRICT;
CREATE INDEX idx_hook_secret_bindings_secret ON hook_secret_bindings(secret_id, hook_id);

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