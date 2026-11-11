CREATE TABLE intel_service_credentials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    rate_window_start TEXT,
    rate_count INTEGER NOT NULL DEFAULT 0
);
