ALTER TABLE advisory_sync_state ADD COLUMN cursor TEXT;
ALTER TABLE advisory_sync_state ADD COLUMN last_run_at TEXT;
ALTER TABLE advisory_sync_state ADD COLUMN records_processed INTEGER NOT NULL DEFAULT 0;
