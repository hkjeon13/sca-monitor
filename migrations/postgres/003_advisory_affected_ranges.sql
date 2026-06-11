ALTER TABLE advisories ADD COLUMN IF NOT EXISTS affected_ranges JSONB NOT NULL DEFAULT '[]'::jsonb;
