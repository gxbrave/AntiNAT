-- AntiNAT gateway traversal schema — migration 0007 (P12).
-- Ownership: plan 12-gateway-traversal-detection. Adds the controller-side
-- mirror of the agent traversal detection: one profile row per node,
-- protocol axis and route fingerprint, plus one result row per strategy
-- attempt. The unique key on results follows the frozen v0.7 rule: node,
-- network fingerprint, protocol, strategy and layer signature. Detection
-- profiles are capability records only — they never bind a Forward
-- endpoint; every Forward acquires, keeps alive and probes independently.
--
-- Conventions mirror migrations 0001-0006: STRICT tables, Unix-second
-- timestamps, structured evidence as JSON text, no secrets.

-- One detection profile per node, protocol axis and fingerprint. A route
-- change produces a new fingerprint and therefore a new profile row; the
-- latest computed_at per (node, protocol) is the current one.
CREATE TABLE node_traversal_profiles (
    id               TEXT PRIMARY KEY,
    node_id          TEXT NOT NULL REFERENCES nodes(id),
    protocol         TEXT NOT NULL,             -- 'tcp' | 'udp'
    fingerprint      TEXT NOT NULL,             -- route-table fingerprint
    default_strategy TEXT,                      -- empty when nothing passed
    profile_json     TEXT NOT NULL,             -- full structured profile
    computed_at      INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    UNIQUE(node_id, protocol, fingerprint)
) STRICT;
CREATE INDEX idx_traversal_profiles_node
    ON node_traversal_profiles(node_id, protocol, computed_at, id);

-- One result row per strategy attempt, deduped by the frozen key (node,
-- fingerprint, protocol, strategy, layer signature). A re-detection under
-- the same fingerprint and mechanism updates the row; a different
-- mechanism signature (e.g. upnp-igd:1 vs upnp-igd:2) is a distinct row.
CREATE TABLE node_traversal_results (
    id              TEXT PRIMARY KEY,
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    profile_id      TEXT NOT NULL REFERENCES node_traversal_profiles(id),
    protocol        TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    strategy        TEXT NOT NULL,
    layer_signature TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL,              -- PASSED | FAILED | EXCLUDED | DEFERRED
    capability      TEXT NOT NULL DEFAULT '',   -- stable capability code on failure
    candidate       TEXT NOT NULL DEFAULT '',   -- temp-detection endpoint (non-binding)
    note            TEXT NOT NULL DEFAULT '',
    evidence_json   TEXT NOT NULL DEFAULT '[]',
    attempted_at    INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE(node_id, fingerprint, protocol, strategy, layer_signature)
) STRICT;
CREATE INDEX idx_traversal_results_node
    ON node_traversal_results(node_id, protocol, attempted_at, id);
CREATE INDEX idx_traversal_results_state
    ON node_traversal_results(state, protocol, attempted_at, id);
