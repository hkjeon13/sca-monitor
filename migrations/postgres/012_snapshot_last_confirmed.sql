ALTER TABLE dependency_snapshots
ADD COLUMN IF NOT EXISTS last_confirmed_at TIMESTAMPTZ;
