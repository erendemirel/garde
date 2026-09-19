-- Bind each issued /validate key to a surface (internal | tenant). Empty
-- audience keeps pre-migration keys usable on any mount until re-issued.
ALTER TABLE tenant_api_keys
    ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT '';
