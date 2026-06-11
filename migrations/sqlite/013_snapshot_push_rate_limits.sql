CREATE TABLE IF NOT EXISTS snapshot_push_rate_limits (
    rate_limit_key TEXT PRIMARY KEY,
    window_start TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
