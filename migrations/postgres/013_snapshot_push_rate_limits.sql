CREATE TABLE IF NOT EXISTS snapshot_push_rate_limits (
    rate_limit_key TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
