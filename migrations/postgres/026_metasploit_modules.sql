CREATE TABLE metasploit_modules (
    module_id TEXT PRIMARY KEY,
    fullname TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    module_type TEXT NOT NULL,
    rank INTEGER NOT NULL,
    check_supported INTEGER NOT NULL,
    module_path TEXT NOT NULL,
    disclosure_date TEXT,
    modified_at TEXT,
    metadata_sha256 TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX idx_metasploit_modules_active ON metasploit_modules(active, module_id);
CREATE TABLE metasploit_module_cves (
    module_id TEXT NOT NULL REFERENCES metasploit_modules(module_id),
    cve_id TEXT NOT NULL,
    PRIMARY KEY(module_id, cve_id)
);
CREATE INDEX idx_metasploit_cve ON metasploit_module_cves(cve_id, module_id);
