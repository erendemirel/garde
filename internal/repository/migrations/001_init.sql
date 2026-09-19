-- Durable authority for garde (PostgreSQL).
-- Applied once under pg_advisory_lock from the application migrate step.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL DEFAULT '',
    mfa_secret_encrypted TEXT,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enforced BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
    groups JSONB NOT NULL DEFAULT '{}'::jsonb,
    pending_updates JSONB,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email));
CREATE INDEX IF NOT EXISTS users_status_idx ON users (status);

CREATE TABLE IF NOT EXISTS permissions (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    definition TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    definition TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permission_visibility (
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_permission_visibility_permission ON permission_visibility(permission_id);
CREATE INDEX IF NOT EXISTS idx_permission_visibility_group ON permission_visibility(group_id);

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pats_user ON personal_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_pats_user_active ON personal_access_tokens(user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS tenant_api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    audience TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_limit INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON tenant_api_keys(tenant_id);
