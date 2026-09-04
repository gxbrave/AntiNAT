-- AntiNAT deployment-profile hardening — migration 0011 (P17).
-- Additive only; P15 created node_deployment_profiles in migration 0009.
-- The index keeps the per-node structured profile lookup bounded and ordered
-- without changing the profile payload or any frozen prior migration.

CREATE INDEX idx_node_deployment_profiles_updated
    ON node_deployment_profiles(updated_at, node_id);
