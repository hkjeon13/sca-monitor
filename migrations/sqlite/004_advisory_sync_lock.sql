ALTER TABLE advisory_sync_state ADD COLUMN lock_owner TEXT;
ALTER TABLE advisory_sync_state ADD COLUMN lock_expires_at TEXT;
