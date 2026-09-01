-- AntiNAT API/metrics schema — migration 0009 (P15).
-- Additive only; migrations 0001-0008 are frozen and must not be rewritten.

CREATE TABLE traffic_ingest_cursors (
    forward_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE traffic_detail_settings (
    forward_id TEXT PRIMARY KEY,
    detailed   INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE traffic_deltas (
    forward_id             TEXT NOT NULL,
    sequence               INTEGER NOT NULL,
    period                 TEXT NOT NULL,
    bytes_in               INTEGER NOT NULL DEFAULT 0,
    bytes_out              INTEGER NOT NULL DEFAULT 0,
    legacy_connection_count INTEGER NOT NULL DEFAULT 0,
    fully_effective        INTEGER NOT NULL,
    created_at             INTEGER NOT NULL,
    PRIMARY KEY (forward_id, sequence)
) STRICT;
CREATE INDEX idx_traffic_deltas_period ON traffic_deltas(period, forward_id, sequence);

CREATE TABLE traffic_rollups (
    forward_id              TEXT NOT NULL,
    period                  TEXT NOT NULL,
    bytes_in                INTEGER NOT NULL DEFAULT 0,
    bytes_out               INTEGER NOT NULL DEFAULT 0,
    legacy_connection_count INTEGER NOT NULL DEFAULT 0,
    fully_effective         INTEGER NOT NULL DEFAULT 1,
    updated_at              INTEGER NOT NULL,
    PRIMARY KEY (forward_id, period)
) STRICT;
CREATE INDEX idx_traffic_rollups_period ON traffic_rollups(period, forward_id);

CREATE TABLE navigation_categories (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    order_index INTEGER NOT NULL DEFAULT 0,
    revision    INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE navigation_items (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT '',
    category_id TEXT NOT NULL REFERENCES navigation_categories(id) ON DELETE CASCADE,
    forward_id  TEXT NOT NULL REFERENCES forwards(id) ON DELETE CASCADE,
    order_index INTEGER NOT NULL DEFAULT 0,
    revision    INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_navigation_categories_order ON navigation_categories(order_index, id);
CREATE INDEX idx_navigation_items_category_order ON navigation_items(category_id, order_index, id);

CREATE TABLE node_traversal_defaults (
    node_id      TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    tcp_strategy TEXT NOT NULL DEFAULT '',
    udp_strategy TEXT NOT NULL DEFAULT '',
    revision     INTEGER NOT NULL DEFAULT 1,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE api_operations (
    id                    TEXT PRIMARY KEY,
    kind                  TEXT NOT NULL,
    node_id               TEXT,
    forward_id            TEXT,
    state                 TEXT NOT NULL,
    detail                TEXT NOT NULL DEFAULT '',
    remote_cleanup_confirmed INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    completed_at          INTEGER
) STRICT;
CREATE INDEX idx_api_operations_kind ON api_operations(kind, created_at, id);

CREATE TABLE node_deployment_profiles (
    node_id      TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    profile_json TEXT NOT NULL,
    revision     INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE api_settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    settings_json TEXT NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 1,
    updated_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE navigation_order (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    category_ids  TEXT NOT NULL,
    item_ids      TEXT NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 1,
    updated_at    INTEGER NOT NULL
) STRICT;
