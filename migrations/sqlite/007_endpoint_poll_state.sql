CREATE TABLE IF NOT EXISTS endpoint_poll_state (
    worker_name TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    lock_owner TEXT,
    lock_expires_at TEXT,
    last_success_at TEXT,
    last_error_at TEXT,
    last_error_message TEXT,
    checked_count INTEGER NOT NULL DEFAULT 0,
    succeeded_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    snapshots_created_or_updated INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
