-- AntiNAT enrollment schema — migration 0003 (P08).
-- Ownership: plan 08-enrollment-control-channel. Adds the durable enrollment
-- result records required by the frozen enrollment contract
-- (docs/protocol.md §4.4): token consumption, credential binding, and the
-- enrollment result ID are committed in one SQLite transaction, and a lost
-- EnrollResult response is recoverable idempotently (same node + same key +
-- valid possession proof returns the original binding result).
--
-- Conventions mirror migrations 0001/0002: STRICT tables, Unix-second
-- timestamps, secret material stored only as hashes.

-- Durable enrollment results. One row per successful credential binding,
-- keyed by (node, agent public key hash, credential version) so the
-- controller can replay the ORIGINAL result after response loss without
-- consuming a second token. The row survives the token lifecycle; it
-- cascades with its node (node_credentials does the same).
CREATE TABLE enrollment_results (
    id                   TEXT PRIMARY KEY,
    node_id              TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    enrollment_result_id TEXT NOT NULL,
    agent_public_key_hash TEXT NOT NULL,
    credential_version   INTEGER NOT NULL,
    controller_key_id    TEXT NOT NULL,
    capability_hash      TEXT NOT NULL,
    expiry_unix          INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    UNIQUE (node_id, agent_public_key_hash, credential_version)
) STRICT;
CREATE INDEX idx_enroll_results_node ON enrollment_results(node_id);

-- The control inbox dedups inbound A2C messages by message_id (frozen
-- protocol.md §3.5). P08 additionally records the agent-side operation id so
-- a redelivered result/receipt (reconnect) can be correlated back to the
-- operation even after the controller outbox row was receipted and GC'd.
ALTER TABLE control_inbox ADD COLUMN operation_id TEXT;
