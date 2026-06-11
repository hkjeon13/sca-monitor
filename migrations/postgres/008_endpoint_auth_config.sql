ALTER TABLE services ADD COLUMN IF NOT EXISTS status_auth_type TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS auth_secret_ref TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS encrypted_auth_config BYTEA;
