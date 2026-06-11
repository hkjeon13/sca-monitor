ALTER TABLE advisories ADD COLUMN first_seen_at TEXT;
UPDATE advisories
SET first_seen_at = COALESCE(modified_at, published_at)
WHERE first_seen_at IS NULL;
