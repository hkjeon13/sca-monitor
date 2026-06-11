CREATE TABLE IF NOT EXISTS accepted_risks (
    id TEXT PRIMARY KEY,
    impact_pk TEXT NOT NULL REFERENCES impacts(id) ON DELETE CASCADE,
    approved_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_accepted_risks_active
ON accepted_risks(impact_pk)
WHERE revoked_at IS NULL;
