CREATE TABLE workspace_users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE workspace_sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES workspace_users(id),
    csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE workspace_setup_tokens (
    token_hash TEXT PRIMARY KEY, email TEXT, is_admin INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL, used_at TEXT
);
CREATE TABLE workspace_login_attempts (
    attempt_key TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, window_start TEXT NOT NULL
);
CREATE TABLE projects (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active', created_by TEXT NOT NULL REFERENCES workspace_users(id),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE project_memberships (
    project_id TEXT NOT NULL REFERENCES projects(id), user_id TEXT NOT NULL REFERENCES workspace_users(id),
    role TEXT NOT NULL CHECK(role IN ('owner','maintainer','viewer')),
    PRIMARY KEY(project_id,user_id)
);
CREATE TABLE project_targets (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    service_pk TEXT NOT NULL UNIQUE REFERENCES services(id), target_key TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
    UNIQUE(project_id,target_key)
);
CREATE TABLE project_alert_rules (
    project_id TEXT PRIMARY KEY REFERENCES projects(id), enabled INTEGER NOT NULL DEFAULT 1,
    minimum_risk TEXT NOT NULL DEFAULT 'high', channel_type TEXT NOT NULL DEFAULT 'webhook',
    target_url TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
);
CREATE INDEX idx_workspace_sessions_user ON workspace_sessions(user_id);
CREATE INDEX idx_memberships_user ON project_memberships(user_id);
CREATE INDEX idx_targets_project ON project_targets(project_id);
CREATE INDEX idx_advisories_source_modified ON advisories(source,modified_at,id);
CREATE INDEX idx_advisories_modified ON advisories(modified_at,id);
