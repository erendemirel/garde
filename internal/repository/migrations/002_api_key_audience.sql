-- Bind each issued /validate key to a surface (internal | tenant).
-- New keys must set audience at issue time; an empty value is refused on
-- mounts that require one.
ALTER TABLE tenant_api_keys
    ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT '';
