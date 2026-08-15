-- AntiNAT probe hardening schema — migration 0005 (P10 cycle-2).
-- Adds the operator's explicit independent-vantage capability declaration.
-- A provider without this declaration may execute a probe exchange for
-- diagnostics, but it cannot create OPEN_FROM_VANTAGE/PUBLISHED_VERIFIED
-- evidence.
ALTER TABLE probe_providers ADD COLUMN independent_vantage INTEGER NOT NULL DEFAULT 0;
