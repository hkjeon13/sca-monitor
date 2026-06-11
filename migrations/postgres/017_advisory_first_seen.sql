ALTER TABLE advisories ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ;
UPDATE advisories
SET first_seen_at = COALESCE(modified_at, published_at)
WHERE first_seen_at IS NULL;
