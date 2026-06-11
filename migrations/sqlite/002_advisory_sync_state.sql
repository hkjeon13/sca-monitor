CREATE TABLE IF NOT EXISTS advisory_sync_state (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    last_success_at TEXT,
    last_error_at TEXT,
    last_error_message TEXT,
    last_advisory_id TEXT,
    imported_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
