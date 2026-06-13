ALTER TABLE services ADD COLUMN IF NOT EXISTS poll_interval_seconds INTEGER;
ALTER TABLE services ADD COLUMN IF NOT EXISTS freshness_threshold_seconds INTEGER;
