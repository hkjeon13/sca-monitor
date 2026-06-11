ALTER TABLE advisory_sync_state ADD COLUMN IF NOT EXISTS cursor TEXT;
ALTER TABLE advisory_sync_state ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMPTZ;
ALTER TABLE advisory_sync_state ADD COLUMN IF NOT EXISTS records_processed INTEGER NOT NULL DEFAULT 0;
