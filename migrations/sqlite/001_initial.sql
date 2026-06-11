CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    owner_team TEXT NOT NULL,
    status_endpoint_url TEXT,
    collection_mode TEXT NOT NULL DEFAULT 'push',
    internet_facing INTEGER NOT NULL DEFAULT 0,
    business_criticality TEXT NOT NULL DEFAULT 'medium',
    alert_channel TEXT,
    latest_snapshot_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(service_id, environment)
);

CREATE TABLE IF NOT EXISTS endpoint_health (
    service_pk TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
    collection_status TEXT NOT NULL DEFAULT 'ok',
    freshness_status TEXT NOT NULL DEFAULT 'fresh',
    last_successful_poll_at TEXT,
    last_error_code TEXT,
    last_error_message TEXT,
    snapshot_age_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dependency_snapshots (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    service_pk TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL,
    environment TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    freshness_status TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    is_latest INTEGER NOT NULL DEFAULT 1,
    artifact_type TEXT,
    artifact_name TEXT,
    artifact_digest TEXT,
    raw_payload TEXT NOT NULL,
    UNIQUE(service_pk, snapshot_id)
);

CREATE TABLE IF NOT EXISTS dependencies (
    id TEXT PRIMARY KEY,
    snapshot_pk TEXT NOT NULL REFERENCES dependency_snapshots(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    canonical_package_name TEXT NOT NULL,
    resolved_version TEXT NOT NULL,
    package_url TEXT,
    dependency_scope TEXT NOT NULL DEFAULT 'production',
    direct_dependency INTEGER NOT NULL DEFAULT 0,
    dependency_path TEXT,
    source TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    canonical_package_name TEXT NOT NULL,
    affected_versions TEXT NOT NULL,
    fixed_version TEXT,
    is_known_exploited INTEGER NOT NULL DEFAULT 0,
    is_malicious_package INTEGER NOT NULL DEFAULT 0,
    published_at TEXT,
    modified_at TEXT,
    raw_payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS impacts (
    id TEXT PRIMARY KEY,
    service_pk TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    advisory_pk TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    dependency_pk TEXT REFERENCES dependencies(id) ON DELETE SET NULL,
    snapshot_pk TEXT REFERENCES dependency_snapshots(id) ON DELETE SET NULL,
    package_name TEXT NOT NULL,
    canonical_package_name TEXT NOT NULL,
    resolved_version TEXT NOT NULL,
    fixed_version TEXT,
    environment TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_detected_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_at TEXT,
    freshness_status TEXT NOT NULL,
    artifact_digest TEXT,
    impact_identity TEXT NOT NULL UNIQUE,
    alert_suppression_key TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS impact_history (
    id TEXT PRIMARY KEY,
    impact_pk TEXT NOT NULL REFERENCES impacts(id) ON DELETE CASCADE,
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
    id TEXT PRIMARY KEY,
    impact_pk TEXT REFERENCES impacts(id) ON DELETE SET NULL,
    alert_suppression_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    channel_type TEXT NOT NULL DEFAULT 'web',
    channel_target TEXT,
    payload TEXT NOT NULL,
    sent_at TEXT,
    created_at TEXT NOT NULL
);
