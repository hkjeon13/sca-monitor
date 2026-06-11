CREATE TABLE IF NOT EXISTS push_credentials (
    id TEXT PRIMARY KEY,
    service_pk TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL
);
