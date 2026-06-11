CREATE TABLE IF NOT EXISTS push_credentials (
    id TEXT PRIMARY KEY,
    service_pk TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes JSONB NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
