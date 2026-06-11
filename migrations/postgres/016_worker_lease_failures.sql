ALTER TABLE advisory_sync_state ADD COLUMN IF NOT EXISTS lease_acquire_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoint_poll_state ADD COLUMN IF NOT EXISTS lease_acquire_failures INTEGER NOT NULL DEFAULT 0;
