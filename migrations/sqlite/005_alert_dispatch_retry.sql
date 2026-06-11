ALTER TABLE alert_events ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_events ADD COLUMN next_attempt_at TEXT;
ALTER TABLE alert_events ADD COLUMN dispatch_lock_owner TEXT;
ALTER TABLE alert_events ADD COLUMN dispatch_lock_expires_at TEXT;
