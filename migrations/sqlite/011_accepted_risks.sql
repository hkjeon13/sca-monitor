CREATE TABLE IF NOT EXISTS accepted_risks (
    id TEXT PRIMARY KEY,
    impact_pk TEXT NOT NULL REFERENCES impacts(id) ON DELETE CASCADE,
    approved_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_accepted_risks_active
ON accepted_risks(impact_pk)
WHERE revoked_at IS NULL;
