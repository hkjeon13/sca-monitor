ALTER TABLE advisory_sync_state ADD COLUMN IF NOT EXISTS lock_owner TEXT;
ALTER TABLE advisory_sync_state ADD COLUMN IF NOT EXISTS lock_expires_at TIMESTAMPTZ;
