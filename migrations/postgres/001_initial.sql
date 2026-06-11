CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    owner_team TEXT NOT NULL,
    status_endpoint_url TEXT,
    collection_mode TEXT NOT NULL DEFAULT 'push',
    internet_facing BOOLEAN NOT NULL DEFAULT false,
    business_criticality TEXT NOT NULL DEFAULT 'medium',
    alert_channel TEXT,
    latest_snapshot_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(service_id, environment)
);

CREATE TABLE IF NOT EXISTS endpoint_health (
    service_pk TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
    collection_status TEXT NOT NULL DEFAULT 'ok',
    freshness_status TEXT NOT NULL DEFAULT 'fresh',
    last_successful_poll_at TIMESTAMPTZ,
    last_error_code TEXT,
    last_error_message TEXT,
    snapshot_age_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS dependency_snapshots (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    service_pk TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL,
    environment TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    source_type TEXT NOT NULL,
    freshness_status TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    is_latest BOOLEAN NOT NULL DEFAULT true,
    artifact_type TEXT,
    artifact_name TEXT,
    artifact_digest TEXT,
    raw_payload JSONB NOT NULL,
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
    direct_dependency BOOLEAN NOT NULL DEFAULT false,
    dependency_path TEXT,
    source TEXT,
    created_at TIMESTAMPTZ NOT NULL
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
    affected_versions JSONB NOT NULL,
    fixed_version TEXT,
    is_known_exploited BOOLEAN NOT NULL DEFAULT false,
    is_malicious_package BOOLEAN NOT NULL DEFAULT false,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    raw_payload JSONB NOT NULL
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
    first_detected_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    freshness_status TEXT NOT NULL,
    artifact_digest TEXT,
    impact_identity TEXT NOT NULL UNIQUE,
    alert_suppression_key TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS impact_history (
    id TEXT PRIMARY KEY,
    impact_pk TEXT NOT NULL REFERENCES impacts(id) ON DELETE CASCADE,
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
    id TEXT PRIMARY KEY,
    impact_pk TEXT REFERENCES impacts(id) ON DELETE SET NULL,
    alert_suppression_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    channel_type TEXT NOT NULL DEFAULT 'web',
    channel_target TEXT,
    payload JSONB NOT NULL,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
