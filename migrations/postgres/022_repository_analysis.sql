CREATE TABLE repository_credentials (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), label TEXT NOT NULL,
 provider TEXT NOT NULL, host TEXT NOT NULL, encrypted_value TEXT NOT NULL,
 key_version TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE repository_connections (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), provider TEXT NOT NULL,
 host TEXT NOT NULL, namespace TEXT NOT NULL, url TEXT NOT NULL, ref TEXT NOT NULL, llm_enabled INTEGER NOT NULL DEFAULT 0,
 subpath TEXT NOT NULL DEFAULT '', credential_id TEXT REFERENCES repository_credentials(id),
 target_id TEXT NOT NULL REFERENCES project_targets(id), created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, last_checked_at TEXT, last_commit TEXT,
 UNIQUE(project_id,url,ref,subpath)
);
CREATE TABLE repository_scan_runs (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 repository_id TEXT NOT NULL REFERENCES repository_connections(id), mode TEXT NOT NULL,
 parent_id TEXT REFERENCES repository_scan_runs(id), requested_by TEXT NOT NULL REFERENCES workspace_users(id),
 idempotency_key TEXT NOT NULL, status TEXT NOT NULL, phase TEXT NOT NULL,
 snapshot TEXT NOT NULL, commit_sha TEXT, archive_sha256 TEXT, report TEXT,
 cancel_requested INTEGER NOT NULL DEFAULT 0, error TEXT, created_at TEXT NOT NULL,
 started_at TEXT, finished_at TEXT, heartbeat_at TEXT,
 UNIQUE(project_id,idempotency_key)
);
CREATE TABLE repository_components (
 id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES repository_scan_runs(id),
 ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT, declared_range TEXT,
 module TEXT NOT NULL, origin TEXT NOT NULL, relationship TEXT NOT NULL,
 evidence TEXT NOT NULL, purl TEXT
);
CREATE TABLE repository_edges (
 scan_id TEXT NOT NULL REFERENCES repository_scan_runs(id),
 parent_id TEXT NOT NULL REFERENCES repository_components(id),
 child_id TEXT NOT NULL REFERENCES repository_components(id),
 PRIMARY KEY(scan_id,parent_id,child_id)
);
CREATE INDEX idx_repository_connections_project ON repository_connections(project_id);
CREATE INDEX idx_repository_credentials_project ON repository_credentials(project_id);
CREATE INDEX idx_repository_scans_queue ON repository_scan_runs(status,created_at);
CREATE INDEX idx_repository_scans_project ON repository_scan_runs(project_id,created_at);
CREATE INDEX idx_repository_components_scan ON repository_components(scan_id,id);
CREATE INDEX idx_repository_edges_child ON repository_edges(scan_id,child_id);

CREATE TABLE repository_llm_settings (
 id INTEGER PRIMARY KEY CHECK(id=1), encrypted_key TEXT NOT NULL, key_version TEXT NOT NULL,
 updated_by TEXT NOT NULL REFERENCES workspace_users(id), updated_at TEXT NOT NULL
);
