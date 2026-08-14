-- AntiNAT probe orchestration schema — migration 0004 (P10).
-- Ownership: plan 10-wan-probe-activation-cli-e2e. Adds the durable probe
-- provider registry and the probe operation/journal rows. The controller-side
-- orthogonal activation mirror already exists in the frozen P06 core schema
-- (forward_activations + forward_runtime_status, migration 0001) and is
-- consumed through store methods, not duplicated here.
--
-- Conventions mirror migrations 0001-0003: STRICT tables, Unix-second
-- timestamps, secret material stored only as hashes (probe keys are public
-- keys, not secrets).

-- Registered probe providers (operator-owned, pinned public keys). The
-- controller requests provider service only for probes whose arm is durably
-- acknowledged (probe_armed), and the provider egress IP is the exact
-- expected_source_ip pinned into the ARM1 frame.
CREATE TABLE probe_providers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    public_key  TEXT NOT NULL,  -- hex ed25519 public key (verifies provider results)
    egress_ip   TEXT NOT NULL,  -- IPv4 literal the provider connects FROM
    endpoint    TEXT NOT NULL,  -- base URL of the antinat-probe service
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

-- Durable probe operations. One row per ARM1; status follows the frozen
-- outcome registry (docs/protocol.md §8) plus intermediate states
-- PENDING/ARMED/IN_FLIGHT. arm_hex is the canonical ARM1 frame bytes so the
-- controller can re-request the provider and re-join after a restart without
-- re-arming the agent.
CREATE TABLE probe_operations (
    id              TEXT PRIMARY KEY,      -- probe_id hex
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    forward_id      TEXT NOT NULL,
    activation_id   TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'PENDING',
    endpoint        TEXT NOT NULL,
    arm_hex         TEXT NOT NULL,
    challenge_hash  TEXT,
    ttl_ms          INTEGER NOT NULL,
    expiry_opaque   TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_probe_ops_node ON probe_operations(node_id);

-- Probe result journal: every joined artifact (provider result, WAN1 frame,
-- ACK1 frame, RCT1 receipt) is persisted per probe for audit and re-join.
CREATE TABLE probe_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id    TEXT NOT NULL REFERENCES probe_operations(id),
    kind        TEXT NOT NULL,  -- provider|wan1|ack1|rct1
    payload_hex TEXT NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_probe_results_probe ON probe_results(probe_id);
