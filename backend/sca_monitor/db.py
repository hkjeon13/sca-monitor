from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def migrate(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
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
                """
            )
            self._seed_advisories(conn)

    def _seed_advisories(self, conn: sqlite3.Connection) -> None:
        seeds = [
            {
                "advisory_id": "DEMO-OSV-LODASH-41720",
                "source": "OSV",
                "summary": "Demo advisory for lodash versions up to 4.17.20",
                "severity": "high",
                "ecosystem": "npm",
                "package_name": "lodash",
                "affected_versions": ["4.17.20", "4.17.19"],
                "fixed_version": "4.17.21",
                "is_known_exploited": False,
                "is_malicious_package": False,
            },
            {
                "advisory_id": "DEMO-MAL-EVENT-STREAM",
                "source": "OpenSSF",
                "summary": "Demo malicious package advisory for event-stream 3.3.6",
                "severity": "critical",
                "ecosystem": "npm",
                "package_name": "event-stream",
                "affected_versions": ["3.3.6"],
                "fixed_version": None,
                "is_known_exploited": False,
                "is_malicious_package": True,
            },
        ]
        for item in seeds:
            existing = conn.execute(
                "SELECT id FROM advisories WHERE advisory_id = ?", (item["advisory_id"],)
            ).fetchone()
            if existing:
                continue
            conn.execute(
                """
                INSERT INTO advisories (
                    id, advisory_id, source, summary, severity, ecosystem, package_name,
                    canonical_package_name, affected_versions, fixed_version,
                    is_known_exploited, is_malicious_package, published_at, modified_at, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    item["advisory_id"],
                    item["source"],
                    item["summary"],
                    item["severity"],
                    item["ecosystem"],
                    item["package_name"],
                    canonical_package_name(item["ecosystem"], item["package_name"]),
                    json.dumps(item["affected_versions"]),
                    item["fixed_version"],
                    int(item["is_known_exploited"]),
                    int(item["is_malicious_package"]),
                    utcnow(),
                    utcnow(),
                    json.dumps(item),
                ),
            )


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def canonical_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "pypi":
        return name.lower().replace("_", "-").replace(".", "-")
    if ecosystem.lower() == "maven":
        return name.lower()
    return name.lower()
