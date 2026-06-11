from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
from contextlib import contextmanager
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import Settings, load_settings
from .db import Database, canonical_package_name, row_to_dict, utcnow
from .osv import AdvisoryImport, fetch_osv_advisory, parse_osv_advisories
from .versioning import version_is_affected


ACTIVE_IMPACT_STATUSES = ("open", "acknowledged", "in_progress")
IMPACT_STATUSES = {
    "open",
    "acknowledged",
    "in_progress",
    "fixed",
    "accepted_risk",
    "false_positive",
    "not_affected",
    "resolved_by_advisory_update",
}


class ScaMonitorApp:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = Database(settings.database_url)
        self.db.migrate()

    def handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "SCAMonitor/0.1"

            def do_GET(self) -> None:
                app.route(self, "GET")

            def do_POST(self) -> None:
                app.route(self, "POST")

            def do_PATCH(self) -> None:
                app.route(self, "PATCH")

            def do_HEAD(self) -> None:
                app.head(self)

            def log_message(self, fmt: str, *args) -> None:
                print("[%s] %s" % (self.log_date_time_string(), fmt % args))

        return Handler

    def head(self, request: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(request.path)
        path = parsed.path
        if path in ("/", "/index.html") or path.startswith("/api/") or path in ("/health", "/ready", "/metrics"):
            request.send_response(HTTPStatus.OK)
            request.send_header("Content-Type", "text/html; charset=utf-8" if path in ("/", "/index.html") else "application/json; charset=utf-8")
            request.send_header("Content-Length", "0")
            request.end_headers()
            return
        request.send_response(HTTPStatus.NOT_FOUND)
        request.send_header("Content-Length", "0")
        request.end_headers()

    def route(self, request: BaseHTTPRequestHandler, method: str) -> None:
        parsed = urlparse(request.path)
        path = parsed.path
        try:
            if path == "/health":
                return self.json_response(request, {"status": "ok", "app": "sca-monitor"})
            if path == "/ready":
                readiness = self.db.readiness()
                status = HTTPStatus.OK if readiness["database"] == "ok" else HTTPStatus.SERVICE_UNAVAILABLE
                return self.json_response(request, {"status": "ready" if status == HTTPStatus.OK else "not_ready", **readiness}, status)
            if path == "/metrics":
                return self.text_response(request, self.metrics(), "text/plain; charset=utf-8")
            if path == "/api/v1/overview" and method == "GET":
                return self.json_response(request, self.overview())
            if path == "/api/v1/services" and method == "GET":
                return self.json_response(request, {"services": self.list_services()})
            if path == "/api/v1/services" and method == "POST":
                return self.json_response(request, self.create_service(self.read_json(request)), HTTPStatus.CREATED)
            if path.startswith("/api/v1/services/") and path.endswith("/push-credentials") and method == "GET":
                service_id = path.split("/")[-2]
                return self.json_response(request, {"credentials": self.list_push_credentials(service_id, parse_qs(parsed.query))})
            if path.startswith("/api/v1/services/") and path.endswith("/push-credentials") and method == "POST":
                service_id = path.split("/")[-2]
                return self.json_response(request, self.create_push_credential(service_id, self.read_json(request)), HTTPStatus.CREATED)
            if path.startswith("/api/v1/services/") and "/push-credentials/" in path and path.endswith("/revoke") and method == "POST":
                parts = path.split("/")
                service_id = parts[-4]
                credential_id = parts[-2]
                return self.json_response(request, self.revoke_push_credential(service_id, credential_id, self.read_json(request)))
            if path.startswith("/api/v1/services/") and method == "GET":
                service_id = path.split("/")[-1]
                return self.json_response(request, self.get_service_detail(service_id))
            if path == "/api/v1/advisories" and method == "GET":
                return self.json_response(request, {"advisories": self.list_advisories(parse_qs(parsed.query))})
            if path == "/api/v1/advisories/osv/import" and method == "POST":
                return self.json_response(request, self.import_osv_advisory(self.read_json(request)), HTTPStatus.CREATED)
            if path == "/api/v1/snapshots" and method == "POST":
                return self.json_response(request, self.push_snapshot(self.read_json(request), request.headers.get("Authorization")), HTTPStatus.CREATED)
            if path == "/api/v1/impacts" and method == "GET":
                return self.json_response(request, self.search_impacts(parse_qs(parsed.query)))
            if path.startswith("/api/v1/impacts/") and method == "GET":
                impact_id = path.split("/")[-1]
                return self.json_response(request, self.get_impact(impact_id))
            if path.startswith("/api/v1/impacts/") and path.endswith("/status") and method == "PATCH":
                impact_id = path.split("/")[-2]
                return self.json_response(request, self.update_impact_status(impact_id, self.read_json(request)))
            if path.startswith("/api/"):
                return self.json_response(request, {"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return self.serve_static(request, path)
        except ValueError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except PermissionError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.FORBIDDEN)
        except Exception as exc:  # noqa: BLE001 - keep MVP server alive and visible.
            return self.json_response(request, {"error": "internal_error", "detail": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def read_json(self, request: BaseHTTPRequestHandler) -> dict:
        length = int(request.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(request.rfile.read(length).decode("utf-8"))

    def json_response(self, request: BaseHTTPRequestHandler, body: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        request.send_response(status)
        request.send_header("Content-Type", "application/json; charset=utf-8")
        request.send_header("Content-Length", str(len(payload)))
        request.end_headers()
        request.wfile.write(payload)

    def text_response(self, request: BaseHTTPRequestHandler, body: str, content_type: str) -> None:
        payload = body.encode("utf-8")
        request.send_response(HTTPStatus.OK)
        request.send_header("Content-Type", content_type)
        request.send_header("Content-Length", str(len(payload)))
        request.end_headers()
        request.wfile.write(payload)

    def serve_static(self, request: BaseHTTPRequestHandler, path: str) -> None:
        requested = "index.html" if path in ("", "/") else path.lstrip("/")
        file_path = (self.settings.frontend_dir / requested).resolve()
        if not str(file_path).startswith(str(self.settings.frontend_dir)):
            return self.json_response(request, {"error": "invalid_path"}, HTTPStatus.BAD_REQUEST)
        if not file_path.exists() or file_path.is_dir():
            file_path = self.settings.frontend_dir / "index.html"
        payload = file_path.read_bytes()
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        request.send_response(HTTPStatus.OK)
        request.send_header("Content-Type", content_type)
        request.send_header("Content-Length", str(len(payload)))
        if file_path.name == "index.html":
            request.send_header("Cache-Control", "no-cache")
        else:
            request.send_header("Cache-Control", "public, max-age=31536000, immutable")
        request.end_headers()
        request.wfile.write(payload)

    def overview(self) -> dict:
        active_status_filter = ",".join("?" for _ in ACTIVE_IMPACT_STATUSES)
        with self.db.connect() as conn:
            service_count = conn.execute("SELECT COUNT(*) AS c FROM services").fetchone()["c"]
            open_impacts = conn.execute(f"SELECT COUNT(*) AS c FROM impacts WHERE status IN ({active_status_filter})", ACTIVE_IMPACT_STATUSES).fetchone()["c"]
            critical = conn.execute(
                f"SELECT COUNT(*) AS c FROM impacts WHERE status IN ({active_status_filter}) AND risk_level = 'critical'",
                ACTIVE_IMPACT_STATUSES,
            ).fetchone()["c"]
            high = conn.execute(
                f"SELECT COUNT(*) AS c FROM impacts WHERE status IN ({active_status_filter}) AND risk_level = 'high'",
                ACTIVE_IMPACT_STATUSES,
            ).fetchone()["c"]
            unhealthy = conn.execute("SELECT COUNT(*) AS c FROM endpoint_health WHERE collection_status != 'ok'").fetchone()["c"]
            advisory_sync = self.advisory_sync_overview(conn)
        return {
            "service_count": service_count,
            "open_impacts": open_impacts,
            "critical_impacts": critical,
            "high_impacts": high,
            "endpoint_unhealthy": unhealthy,
            "advisory_sync": advisory_sync,
            "system": {"environment": self.settings.app_env},
        }

    def advisory_sync_overview(self, conn) -> dict:
        sync = {"OSV": "seeded-demo", "CISA_KEV": "pending"}
        try:
            rows = conn.execute("SELECT source, status FROM advisory_sync_state").fetchall()
        except Exception:
            return sync
        for row in rows:
            sync[row["source"]] = row["status"]
        return sync

    def list_services(self) -> list[dict]:
        active_status_filter = ",".join("?" for _ in ACTIVE_IMPACT_STATUSES)
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT s.*, eh.collection_status, eh.freshness_status,
                       (SELECT COUNT(*) FROM impacts i WHERE i.service_pk = s.id AND i.status IN ({active_status_filter})) AS open_impacts
                FROM services s
                LEFT JOIN endpoint_health eh ON eh.service_pk = s.id
                ORDER BY s.updated_at DESC
                """,
                ACTIVE_IMPACT_STATUSES,
            ).fetchall()
        return [row_to_dict(row) for row in rows]

    def create_service(self, body: dict) -> dict:
        service_id = required(body, "service_id")
        environment = body.get("environment", "prod")
        now = utcnow()
        service_pk = str(uuid.uuid4())
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO services (
                    id, service_id, service_name, environment, owner_team,
                    status_endpoint_url, collection_mode, internet_facing,
                    business_criticality, alert_channel, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_id, environment) DO UPDATE SET
                    service_name=excluded.service_name,
                    owner_team=excluded.owner_team,
                    status_endpoint_url=excluded.status_endpoint_url,
                    collection_mode=excluded.collection_mode,
                    internet_facing=excluded.internet_facing,
                    business_criticality=excluded.business_criticality,
                    alert_channel=excluded.alert_channel,
                    updated_at=excluded.updated_at
                """,
                (
                    service_pk,
                    service_id,
                    body.get("service_name", service_id),
                    environment,
                    body.get("owner_team", "unassigned"),
                    body.get("status_endpoint_url"),
                    body.get("collection_mode", "push"),
                    int(bool(body.get("internet_facing", False))),
                    body.get("business_criticality", "medium"),
                    body.get("alert_channel", "#security-alerts"),
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM services WHERE service_id = ? AND environment = ?", (service_id, environment)).fetchone()
            conn.execute(
                """
                INSERT OR REPLACE INTO endpoint_health (
                    service_pk, collection_status, freshness_status, updated_at
                ) VALUES (?, 'ok', 'fresh', ?)
                """,
                (row["id"], now),
            )
        return {"service": row_to_dict(row)}

    def list_push_credentials(self, service_id: str, query: dict[str, list[str]]) -> list[dict]:
        environment = query.get("environment", ["prod"])[0]
        with self.db.connect() as conn:
            service = conn.execute(
                "SELECT id FROM services WHERE service_id = ? AND environment = ?",
                (service_id, environment),
            ).fetchone()
            if not service:
                raise ValueError("service not found")
            rows = conn.execute(
                """
                SELECT id, token_prefix, scopes, expires_at, revoked_at, last_used_at, created_at
                FROM push_credentials
                WHERE service_pk = ?
                ORDER BY created_at DESC
                """,
                (service["id"],),
            ).fetchall()
        credentials = []
        for row in rows:
            item = row_to_dict(row)
            item["scopes"] = json.loads(item["scopes"]) if isinstance(item["scopes"], str) else item["scopes"]
            credentials.append(item)
        return credentials

    def create_push_credential(self, service_id: str, body: dict) -> dict:
        environment = body.get("environment", "prod")
        scopes = body.get("scopes") or ["snapshot:push"]
        if not isinstance(scopes, list) or "snapshot:push" not in scopes:
            raise ValueError("scopes must include snapshot:push")
        ttl_days = bounded_int(body.get("ttl_days"), default=90, minimum=1, maximum=3650)
        now = utcnow()
        expires_at = utcnow_after_seconds(ttl_days * 24 * 60 * 60)
        token = f"sca_{secrets.token_urlsafe(32)}"
        token_hash = hash_token(token)
        credential_id = str(uuid.uuid4())
        with self.db.connect() as conn:
            service = conn.execute(
                "SELECT id, service_id, environment FROM services WHERE service_id = ? AND environment = ?",
                (service_id, environment),
            ).fetchone()
            if not service:
                raise ValueError("service not found")
            conn.execute(
                """
                INSERT INTO push_credentials (
                    id, service_pk, token_hash, token_prefix, scopes, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (credential_id, service["id"], token_hash, token[:12], json.dumps(scopes), expires_at, now),
            )
        credential = {
            "id": credential_id,
            "service_id": service_id,
            "environment": environment,
            "token_prefix": token[:12],
            "scopes": scopes,
            "expires_at": expires_at,
            "created_at": now,
        }
        return {
            "credential": credential,
            "token": token,
            "usage": {
                "header": "Authorization: Bearer <token>",
                "curl": f"curl -X POST /api/v1/snapshots -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' --data @snapshot.json",
            },
        }

    def revoke_push_credential(self, service_id: str, credential_id: str, body: dict) -> dict:
        environment = body.get("environment", "prod")
        now = utcnow()
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT pc.id, pc.token_prefix, pc.scopes, pc.expires_at, pc.revoked_at, pc.last_used_at, pc.created_at,
                       s.service_id, s.environment
                FROM push_credentials pc
                JOIN services s ON s.id = pc.service_pk
                WHERE pc.id = ? AND s.service_id = ? AND s.environment = ?
                """,
                (credential_id, service_id, environment),
            ).fetchone()
            if not row:
                raise ValueError("push credential not found")
            revoked_at = row["revoked_at"] or now
            if not row["revoked_at"]:
                conn.execute("UPDATE push_credentials SET revoked_at = ? WHERE id = ?", (revoked_at, credential_id))
        credential = row_to_dict(row)
        credential["scopes"] = json.loads(credential["scopes"]) if isinstance(credential["scopes"], str) else credential["scopes"]
        credential["revoked_at"] = revoked_at
        return {"credential": credential}

    def list_advisories(self, query: dict[str, list[str]]) -> list[dict]:
        where = []
        params = []
        if source := query.get("source", [None])[0]:
            where.append("source = ?")
            params.append(source)
        if ecosystem := query.get("ecosystem", [None])[0]:
            where.append("ecosystem = ?")
            params.append(ecosystem)
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT advisory_id, source, summary, severity, ecosystem, package_name,
                       affected_versions, affected_ranges, fixed_version, is_known_exploited,
                       is_malicious_package, published_at, modified_at
                FROM advisories
                {sql_where}
                ORDER BY COALESCE(modified_at, published_at, advisory_id) DESC
                LIMIT 200
                """,
                tuple(params),
            ).fetchall()
        advisories = []
        for row in rows:
            advisory = row_to_dict(row)
            advisory["affected_versions"] = json.loads(advisory["affected_versions"])
            advisory["affected_ranges"] = json.loads(advisory["affected_ranges"])
            advisory["is_known_exploited"] = bool(advisory["is_known_exploited"])
            advisory["is_malicious_package"] = bool(advisory["is_malicious_package"])
            advisories.append(advisory)
        return advisories

    def import_osv_advisory(self, body: dict) -> dict:
        advisory_id = required(body, "advisory_id")
        try:
            payload = fetch_osv_advisory(advisory_id)
            result = self.import_osv_payload(payload)
            return {"source": "OSV", "advisory_id": advisory_id, **result}
        except Exception as exc:
            self.record_advisory_sync("OSV", "error", advisory_id, str(exc))
            raise

    def import_osv_payload(self, payload: dict) -> dict:
        advisories = parse_osv_advisories(payload)
        source_advisory_id = str(payload.get("id") or advisories[0].advisory_id)
        changed_advisories: list[AdvisoryImport] = []
        rematched_impacts = 0
        with self.db.connect() as conn:
            for advisory in advisories:
                if self.upsert_advisory(conn, advisory):
                    changed_advisories.append(advisory)
            for advisory in changed_advisories:
                rematched_impacts += self.rematch_latest_snapshots_for_advisory(conn, advisory)
            self.record_advisory_sync("OSV", "ok", source_advisory_id, None, conn=conn, imported_count=len(advisories))
        return {
            "imported": len(advisories),
            "changed": len(changed_advisories),
            "rematched_impacts": rematched_impacts,
        }

    def upsert_advisory(self, conn, advisory: AdvisoryImport) -> bool:
        previous = conn.execute(
            """
            SELECT summary, severity, ecosystem, package_name, canonical_package_name,
                   affected_versions, affected_ranges, fixed_version, is_known_exploited,
                   is_malicious_package, published_at, modified_at, raw_payload
            FROM advisories
            WHERE advisory_id = ?
            """,
            (advisory.advisory_id,),
        ).fetchone()
        next_values = {
            "summary": advisory.summary,
            "severity": advisory.severity,
            "ecosystem": advisory.ecosystem,
            "package_name": advisory.package_name,
            "canonical_package_name": advisory.canonical_package_name,
            "affected_versions": json.dumps(advisory.affected_versions),
            "affected_ranges": json.dumps(advisory.affected_ranges),
            "fixed_version": advisory.fixed_version,
            "is_known_exploited": int(advisory.is_known_exploited),
            "is_malicious_package": int(advisory.is_malicious_package),
            "published_at": advisory.published_at,
            "modified_at": advisory.modified_at,
            "raw_payload": json.dumps(advisory.raw_payload, ensure_ascii=False),
        }
        changed = previous is None or any(previous[key] != value for key, value in next_values.items())
        conn.execute(
            """
            INSERT INTO advisories (
                id, advisory_id, source, summary, severity, ecosystem, package_name,
                canonical_package_name, affected_versions, affected_ranges, fixed_version,
                is_known_exploited, is_malicious_package, published_at, modified_at, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(advisory_id) DO UPDATE SET
                source=excluded.source,
                summary=excluded.summary,
                severity=excluded.severity,
                ecosystem=excluded.ecosystem,
                package_name=excluded.package_name,
                canonical_package_name=excluded.canonical_package_name,
                affected_versions=excluded.affected_versions,
                affected_ranges=excluded.affected_ranges,
                fixed_version=excluded.fixed_version,
                is_known_exploited=excluded.is_known_exploited,
                is_malicious_package=excluded.is_malicious_package,
                published_at=excluded.published_at,
                modified_at=excluded.modified_at,
                raw_payload=excluded.raw_payload
            """,
            (
                str(uuid.uuid4()),
                advisory.advisory_id,
                advisory.source,
                advisory.summary,
                advisory.severity,
                advisory.ecosystem,
                advisory.package_name,
                advisory.canonical_package_name,
                json.dumps(advisory.affected_versions),
                json.dumps(advisory.affected_ranges),
                advisory.fixed_version,
                int(advisory.is_known_exploited),
                int(advisory.is_malicious_package),
                advisory.published_at,
                advisory.modified_at,
                json.dumps(advisory.raw_payload, ensure_ascii=False),
            ),
        )
        return changed

    def rematch_latest_snapshots_for_advisory(self, conn, advisory: AdvisoryImport) -> int:
        rows = conn.execute(
            """
            SELECT DISTINCT ds.service_pk, ds.id AS snapshot_pk
            FROM dependency_snapshots ds
            JOIN dependencies d ON d.snapshot_pk = ds.id
            WHERE ds.is_latest = 1
              AND d.ecosystem = ?
              AND d.canonical_package_name = ?
            """,
            (advisory.ecosystem, advisory.canonical_package_name),
        ).fetchall()
        count = 0
        for row in rows:
            count += self.match_impacts(conn, row["service_pk"], row["snapshot_pk"])
        return count

    def record_advisory_sync(
        self,
        source: str,
        status: str,
        advisory_id: str | None,
        error_message: str | None,
        conn=None,
        imported_count: int = 0,
    ) -> None:
        now = utcnow()

        def write(connection) -> None:
            connection.execute(
                """
                INSERT INTO advisory_sync_state (
                    source, status, last_success_at, last_error_at, last_error_message,
                    last_advisory_id, imported_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    status=excluded.status,
                    last_success_at=COALESCE(excluded.last_success_at, advisory_sync_state.last_success_at),
                    last_error_at=COALESCE(excluded.last_error_at, advisory_sync_state.last_error_at),
                    last_error_message=excluded.last_error_message,
                    last_advisory_id=excluded.last_advisory_id,
                    imported_count=advisory_sync_state.imported_count + excluded.imported_count,
                    updated_at=excluded.updated_at
                """,
                (
                    source,
                    status,
                    now if status == "ok" else None,
                    now if status != "ok" else None,
                    error_message,
                    advisory_id,
                    imported_count,
                    now,
                ),
            )

        if conn is not None:
            write(conn)
            return
        with self.db.connect() as connection:
            write(connection)

    @contextmanager
    def advisory_sync_lock(self, source: str, owner: str, ttl_seconds: int = 3600):
        now = utcnow()
        expires_at = utcnow_after_seconds(ttl_seconds)
        with self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO advisory_sync_state (source, status, imported_count, updated_at)
                VALUES (?, 'pending', 0, ?)
                ON CONFLICT(source) DO NOTHING
                """,
                (source, now),
            )
            updated = conn.execute(
                """
                UPDATE advisory_sync_state
                SET lock_owner = ?, lock_expires_at = ?, updated_at = ?
                WHERE source = ?
                  AND (lock_owner IS NULL OR lock_owner = ? OR lock_expires_at IS NULL OR lock_expires_at < ?)
                """,
                (owner, expires_at, now, source, owner, now),
            ).rowcount
            if updated != 1:
                row = conn.execute(
                    "SELECT lock_owner, lock_expires_at FROM advisory_sync_state WHERE source = ?",
                    (source,),
                ).fetchone()
                raise RuntimeError(f"{source} sync lock is held by {row['lock_owner']} until {row['lock_expires_at']}")
        try:
            yield
        finally:
            with self.db.connect() as conn:
                conn.execute(
                    """
                    UPDATE advisory_sync_state
                    SET lock_owner = NULL, lock_expires_at = NULL, updated_at = ?
                    WHERE source = ? AND lock_owner = ?
                    """,
                    (utcnow(), source, owner),
                )

    def get_service_detail(self, service_id: str) -> dict:
        with self.db.connect() as conn:
            service = conn.execute("SELECT * FROM services WHERE service_id = ?", (service_id,)).fetchone()
            if not service:
                raise ValueError("service not found")
            impacts = conn.execute("SELECT * FROM impacts WHERE service_pk = ? ORDER BY updated_at DESC", (service["id"],)).fetchall()
        return {"service": row_to_dict(service), "impacts": [row_to_dict(row) for row in impacts]}

    def push_snapshot(self, body: dict, authorization: str | None = None) -> dict:
        service_id = required(body, "service_id")
        environment = body.get("environment", "prod")
        dependencies = body.get("dependencies") or []
        if not dependencies:
            raise ValueError("dependencies required")
        if authorization:
            self.validate_push_authorization(authorization, service_id, environment)
        service = self.create_service(
            {
                "service_id": service_id,
                "service_name": body.get("service_name", service_id),
                "environment": environment,
                "owner_team": body.get("owner_team", "unassigned"),
                "collection_mode": "push",
            }
        )["service"]
        normalized = json.dumps(dependencies, sort_keys=True)
        content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        snapshot_pk = str(uuid.uuid4())
        snapshot_id = body.get("snapshot_id", f"{service_id}-{content_hash[:12]}")
        now = utcnow()
        artifact = body.get("artifact") or {}
        with self.db.connect() as conn:
            existing = conn.execute(
                "SELECT id FROM dependency_snapshots WHERE service_pk = ? AND snapshot_id = ?",
                (service["id"], snapshot_id),
            ).fetchone()
            if existing:
                snapshot_pk = existing["id"]
            else:
                conn.execute("UPDATE dependency_snapshots SET is_latest = 0 WHERE service_pk = ?", (service["id"],))
                conn.execute(
                    """
                    INSERT INTO dependency_snapshots (
                        id, snapshot_id, service_pk, schema_version, environment, generated_at,
                        collected_at, source_type, freshness_status, content_hash, is_latest,
                        artifact_type, artifact_name, artifact_digest, raw_payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'push', 'fresh', ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_pk,
                        snapshot_id,
                        service["id"],
                        body.get("schema_version", "1.0"),
                        environment,
                        body.get("generated_at", now),
                        now,
                        content_hash,
                        artifact.get("type"),
                        artifact.get("name"),
                        artifact.get("digest"),
                        json.dumps(body, ensure_ascii=False),
                    ),
                )
                conn.execute("UPDATE services SET latest_snapshot_id = ?, updated_at = ? WHERE id = ?", (snapshot_pk, now, service["id"]))
                for dep in dependencies:
                    ecosystem = required(dep, "ecosystem")
                    name = required(dep, "name")
                    canonical = canonical_package_name(ecosystem, name)
                    conn.execute(
                        """
                        INSERT INTO dependencies (
                            id, snapshot_pk, ecosystem, package_name, canonical_package_name,
                            resolved_version, package_url, dependency_scope, direct_dependency,
                            dependency_path, source, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(uuid.uuid4()),
                            snapshot_pk,
                            ecosystem,
                            name,
                            canonical,
                            required(dep, "version"),
                            dep.get("purl"),
                            dep.get("scope", "production"),
                            int(bool(dep.get("direct", False))),
                            json.dumps(dep.get("dependency_path", [])),
                            dep.get("source"),
                            now,
                        ),
                    )
            impacts = self.match_impacts(conn, service["id"], snapshot_pk)
        return {"snapshot_id": snapshot_id, "content_hash": content_hash, "impacts_created_or_updated": impacts}

    def validate_push_authorization(self, authorization: str, service_id: str, environment: str) -> None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise PermissionError("invalid authorization scheme")
        now = utcnow()
        token_hash = hash_token(token)
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT pc.id, pc.scopes, pc.expires_at, pc.revoked_at, s.service_id, s.environment
                FROM push_credentials pc
                JOIN services s ON s.id = pc.service_pk
                WHERE pc.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if not row:
                raise PermissionError("invalid push credential")
            if row["revoked_at"]:
                raise PermissionError("push credential revoked")
            if row["expires_at"] and row["expires_at"] <= now:
                raise PermissionError("push credential expired")
            scopes = json.loads(row["scopes"])
            if "snapshot:push" not in scopes:
                raise PermissionError("push credential lacks snapshot:push scope")
            if row["service_id"] != service_id or row["environment"] != environment:
                raise PermissionError("push credential is not bound to this service environment")
            conn.execute("UPDATE push_credentials SET last_used_at = ? WHERE id = ?", (now, row["id"]))

    def match_impacts(self, conn, service_pk: str, snapshot_pk: str) -> int:
        service = conn.execute("SELECT * FROM services WHERE id = ?", (service_pk,)).fetchone()
        snapshot = conn.execute("SELECT * FROM dependency_snapshots WHERE id = ?", (snapshot_pk,)).fetchone()
        deps = conn.execute("SELECT * FROM dependencies WHERE snapshot_pk = ?", (snapshot_pk,)).fetchall()
        count = 0
        now = utcnow()
        for dep in deps:
            advisories = conn.execute(
                """
                SELECT * FROM advisories
                WHERE ecosystem = ? AND canonical_package_name = ?
                """,
                (dep["ecosystem"], dep["canonical_package_name"]),
            ).fetchall()
            for adv in advisories:
                affected_versions = json.loads(adv["affected_versions"])
                affected_ranges = json.loads(adv["affected_ranges"])
                if not version_is_affected(dep["resolved_version"], affected_versions, affected_ranges):
                    continue
                risk = "critical" if adv["is_malicious_package"] or adv["is_known_exploited"] or adv["severity"] == "critical" else adv["severity"]
                identity = ":".join([service["service_id"], service["environment"], adv["advisory_id"], dep["canonical_package_name"]])
                alert_key = ":".join([identity, risk, "open"])
                impact_pk = str(uuid.uuid4())
                existing = conn.execute("SELECT id FROM impacts WHERE impact_identity = ?", (identity,)).fetchone()
                if existing:
                    impact_pk = existing["id"]
                    conn.execute(
                        """
                        UPDATE impacts SET dependency_pk=?, snapshot_pk=?, resolved_version=?, fixed_version=?,
                            risk_level=?, risk_reason=?, status=CASE WHEN status='fixed' THEN 'open' ELSE status END,
                            last_seen_at=?, freshness_status=?, artifact_digest=?, alert_suppression_key=?, updated_at=?
                        WHERE id=?
                        """,
                        (
                            dep["id"],
                            snapshot_pk,
                            dep["resolved_version"],
                            adv["fixed_version"],
                            risk,
                            adv["summary"],
                            now,
                            snapshot["freshness_status"],
                            snapshot["artifact_digest"],
                            alert_key,
                            now,
                            impact_pk,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO impacts (
                            id, service_pk, advisory_pk, dependency_pk, snapshot_pk, package_name,
                            canonical_package_name, resolved_version, fixed_version, environment,
                            risk_level, risk_reason, status, first_detected_at, last_seen_at,
                            freshness_status, artifact_digest, impact_identity, alert_suppression_key, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            impact_pk,
                            service_pk,
                            adv["id"],
                            dep["id"],
                            snapshot_pk,
                            dep["package_name"],
                            dep["canonical_package_name"],
                            dep["resolved_version"],
                            adv["fixed_version"],
                            service["environment"],
                            risk,
                            adv["summary"],
                            now,
                            now,
                            snapshot["freshness_status"],
                            snapshot["artifact_digest"],
                            identity,
                            alert_key,
                            now,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO alert_events (id, impact_pk, alert_suppression_key, reason, status, payload, created_at)
                        VALUES (?, ?, ?, 'new', 'pending', ?, ?)
                        """,
                        (str(uuid.uuid4()), impact_pk, alert_key, json.dumps({"impact_id": impact_pk, "risk_level": risk}), now),
                    )
                count += 1
        return count

    def list_impacts(self, query: dict[str, list[str]]) -> list[dict]:
        return self.search_impacts(query)["impacts"]

    def search_impacts(self, query: dict[str, list[str]]) -> dict:
        where = []
        params = []
        if status := query.get("status", [None])[0]:
            where.append("i.status = ?")
            params.append(status)
        if risk_level := query.get("risk_level", [None])[0]:
            where.append("i.risk_level = ?")
            params.append(risk_level)
        if service_id := query.get("service_id", [None])[0]:
            where.append("s.service_id = ?")
            params.append(service_id)
        if owner_team := query.get("owner_team", [None])[0]:
            where.append("s.owner_team = ?")
            params.append(owner_team)
        if environment := query.get("environment", [None])[0]:
            where.append("i.environment = ?")
            params.append(environment)
        if package_name := query.get("package_name", [None])[0]:
            where.append("i.canonical_package_name = ?")
            params.append(canonical_package_name("", package_name))
        if advisory_id := query.get("advisory_id", [None])[0]:
            where.append("a.advisory_id = ?")
            params.append(advisory_id)
        if search := query.get("q", [None])[0]:
            like = f"%{search.lower()}%"
            where.append(
                """
                (
                    lower(s.service_id) LIKE ?
                    OR lower(s.service_name) LIKE ?
                    OR lower(s.owner_team) LIKE ?
                    OR lower(i.package_name) LIKE ?
                    OR lower(i.canonical_package_name) LIKE ?
                    OR lower(a.advisory_id) LIKE ?
                    OR lower(a.summary) LIKE ?
                )
                """
            )
            params.extend([like] * 7)
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        limit = bounded_int(query.get("limit", [None])[0], default=50, minimum=1, maximum=200)
        offset = bounded_int(query.get("offset", [None])[0], default=0, minimum=0, maximum=1_000_000)
        sort = query.get("sort", ["risk"])[0]
        direction = query.get("direction", ["asc"])[0].lower()
        if direction not in {"asc", "desc"}:
            direction = "asc"
        sort_columns = {
            "risk": "CASE i.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            "updated_at": "i.updated_at",
            "first_detected_at": "i.first_detected_at",
            "last_seen_at": "i.last_seen_at",
            "service": "lower(s.service_id)",
            "package": "lower(i.package_name)",
            "status": "i.status",
        }
        order_expr = sort_columns.get(sort, sort_columns["risk"])
        with self.db.connect() as conn:
            total = conn.execute(
                f"""
                SELECT COUNT(*) AS c
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                JOIN advisories a ON a.id = i.advisory_pk
                {sql_where}
                """,
                tuple(params),
            ).fetchone()["c"]
            rows = conn.execute(
                f"""
                SELECT i.*, s.service_id, s.service_name, a.advisory_id, a.summary
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                JOIN advisories a ON a.id = i.advisory_pk
                {sql_where}
                ORDER BY {order_expr} {direction.upper()}, i.updated_at DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params + [limit, offset]),
            ).fetchall()
        return {
            "impacts": [row_to_dict(row) for row in rows],
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "returned": len(rows),
                "next_offset": offset + limit if offset + limit < total else None,
                "prev_offset": max(offset - limit, 0) if offset > 0 else None,
                "sort": sort if sort in sort_columns else "risk",
                "direction": direction,
            },
        }

    def get_impact(self, impact_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT i.*, s.service_id, s.service_name, a.advisory_id, a.summary, a.source,
                       a.affected_versions, a.affected_ranges
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                JOIN advisories a ON a.id = i.advisory_pk
                WHERE i.id = ?
                """,
                (impact_id,),
            ).fetchone()
            history_rows = conn.execute(
                """
                SELECT from_status, to_status, actor, reason, created_at
                FROM impact_history
                WHERE impact_pk = ?
                ORDER BY created_at DESC
                """,
                (impact_id,),
            ).fetchall()
        if not row:
            raise ValueError("impact not found")
        impact = row_to_dict(row)
        impact["affected_versions"] = json.loads(impact["affected_versions"] or "[]")
        impact["affected_ranges"] = json.loads(impact["affected_ranges"] or "[]")
        return {"impact": impact, "history": [row_to_dict(history) for history in history_rows]}

    def update_impact_status(self, impact_id: str, body: dict) -> dict:
        status = required(body, "status")
        if status not in IMPACT_STATUSES:
            raise ValueError(f"status must be one of {', '.join(sorted(IMPACT_STATUSES))}")
        reason = body.get("reason")
        actor = body.get("actor", "system")
        now = utcnow()
        with self.db.connect() as conn:
            current = conn.execute("SELECT status FROM impacts WHERE id = ?", (impact_id,)).fetchone()
            if not current:
                raise ValueError("impact not found")
            conn.execute("UPDATE impacts SET status = ?, resolved_at = CASE WHEN ? = 'fixed' THEN ? ELSE resolved_at END, updated_at = ? WHERE id = ?", (status, status, now, now, impact_id))
            conn.execute(
                "INSERT INTO impact_history (id, impact_pk, from_status, to_status, actor, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), impact_id, current["status"], status, actor, reason, now),
            )
        return {"impact_id": impact_id, "status": status}

    def metrics(self) -> str:
        overview = self.overview()
        return "\n".join(
            [
                f"sca_monitor_services {overview['service_count']}",
                f"sca_monitor_open_impacts {overview['open_impacts']}",
                f"sca_monitor_critical_impacts {overview['critical_impacts']}",
                f"sca_monitor_endpoint_unhealthy {overview['endpoint_unhealthy']}",
                "",
            ]
        )


def required(data: dict, key: str) -> str:
    value = data.get(key)
    if value is None or value == "":
        raise ValueError(f"{key} required")
    return str(value)


def bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(number, maximum))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utcnow_after_seconds(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def run() -> None:
    settings = load_settings()
    app = ScaMonitorApp(settings)
    server = ThreadingHTTPServer((settings.host, settings.port), app.handler())
    print(f"SCA Monitor listening on http://{settings.host}:{settings.port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
