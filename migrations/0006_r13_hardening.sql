-- AntiNAT R13 hardening schema — migration 0006 (P10 R14).
--
-- This migration replaces the former out-of-ledger ensureR13Schema step. It is
-- append-only: migration files 0001-0005 are never rewritten. The runner may
-- omit an ALTER statement when upgrading an older R13 build that already
-- installed that column outside schema_migrations; all other objects use
-- idempotent DDL and the migration row is recorded in the same transaction.

ALTER TABLE control_outbox ADD COLUMN command_message_id TEXT;
ALTER TABLE control_outbox ADD COLUMN operation_complete_message_id TEXT;
ALTER TABLE control_outbox ADD COLUMN controller_operation_complete_message_id TEXT;
ALTER TABLE probe_operations ADD COLUMN expected_forward_revision INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_control_outbox_command_message
    ON control_outbox(node_id, command_message_id)
    WHERE command_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_control_outbox_operation_complete_message
    ON control_outbox(node_id, operation_complete_message_id)
    WHERE operation_complete_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_control_outbox_controller_operation_complete_message
    ON control_outbox(node_id, controller_operation_complete_message_id)
    WHERE controller_operation_complete_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS probe_terminal_deliveries (
    probe_id     TEXT PRIMARY KEY REFERENCES probe_operations(id),
    disposition  TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    node_id      TEXT NOT NULL,
    forward_id   TEXT NOT NULL,
    activation_id TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_probe_terminal_delivery_state
    ON probe_terminal_deliveries(disposition, updated_at, probe_id);

-- Older R13 candidates used updated_at for this lookup. Recreate the named
-- index with the canonical created_at ordering in the versioned migration.
DROP INDEX IF EXISTS idx_probe_terminal_delivery;
CREATE INDEX idx_probe_terminal_delivery
    ON probe_operations(status, created_at, id);

-- R16 bounded recovery/cleanup paths use deterministic id ordering. These
-- indexes keep the bounded keyset scans from sorting the historical tables.
CREATE INDEX IF NOT EXISTS idx_control_inbox_replay_gc
    ON control_inbox(message_type, state, updated_at, id)
    WHERE message_type = 'probe_result' AND state = 'PROCESSED';
CREATE INDEX IF NOT EXISTS idx_control_inbox_state_page
    ON control_inbox(state, message_type, id);
CREATE INDEX IF NOT EXISTS idx_probe_terminal_expiry
    ON probe_terminal_deliveries(disposition, updated_at, probe_id)
    WHERE disposition = 'ENQUEUED';

-- Probe-operation cleanup uses different durable clocks. Keep the ordered key
-- first in each partial index so a caller-sized LIMIT bounds work rather than
-- merely truncating a full historical sort.
CREATE INDEX IF NOT EXISTS idx_probe_live_expiry
    ON probe_operations(expires_at, id)
    WHERE status IN ('PENDING', 'ARMED', 'IN_FLIGHT');
CREATE INDEX IF NOT EXISTS idx_probe_terminal_created
    ON probe_operations(created_at, id)
    WHERE status IN ('OPEN_FROM_VANTAGE', 'REJECTED', 'DROPPED', 'TIMEOUT', 'NO_INDEPENDENT_VANTAGE', 'PROBE_INFRA_UNAVAILABLE');
CREATE INDEX IF NOT EXISTS idx_probe_terminal_updated
    ON probe_operations(updated_at, id)
    WHERE status IN ('OPEN_FROM_VANTAGE', 'REJECTED', 'DROPPED', 'TIMEOUT', 'NO_INDEPENDENT_VANTAGE', 'PROBE_INFRA_UNAVAILABLE');
