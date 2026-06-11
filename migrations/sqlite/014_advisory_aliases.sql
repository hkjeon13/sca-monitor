CREATE TABLE IF NOT EXISTS advisory_aliases (
    id TEXT PRIMARY KEY,
    advisory_pk TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    alias_type TEXT NOT NULL,
    alias_value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(advisory_pk, alias_value)
);

CREATE INDEX IF NOT EXISTS idx_advisory_aliases_value
ON advisory_aliases(alias_type, alias_value);
