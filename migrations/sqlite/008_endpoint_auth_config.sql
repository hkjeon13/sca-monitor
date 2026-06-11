ALTER TABLE services ADD COLUMN status_auth_type TEXT;
ALTER TABLE services ADD COLUMN auth_secret_ref TEXT;
ALTER TABLE services ADD COLUMN encrypted_auth_config TEXT;
