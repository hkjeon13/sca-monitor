from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import secrets
from contextlib import contextmanager
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import Settings, env_flag, load_settings
from .db import Database, canonical_package_name, json_column, row_to_dict, utcnow
from .osv import AdvisoryImport, fetch_osv_advisory, parse_osv_advisories
from .postgres_cutover import assess_cutover, summarize_preflight
from .versioning import version_is_affected


ACTIVE_IMPACT_STATUSES = ("open", "acknowledged", "in_progress")
INITIAL_ADVISORY_SYNC_SOURCES = ("OSV", "CISA_KEV", "OpenSSF")
RISK_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
DEFAULT_SLA_HOURS = {
    "critical": 24,
    "high": 72,
    "medium": 7 * 24,
    "low": 30 * 24,
    "info": 30 * 24,
}
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
BULK_IMPACT_TARGET_STATUSES = {
    "open",
    "acknowledged",
    "in_progress",
    "fixed",
    "false_positive",
    "not_affected",
}


class PayloadTooLargeError(ValueError):
    pass


class SnapshotConflictError(ValueError):
    pass


class RateLimitError(ValueError):
    pass


class ScaMonitorApp:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = Database(settings.database_url)
        if settings.auto_migrate:
            self.db.migrate()
            self.rebuild_missing_advisory_aliases()

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
                readiness = self.database_readiness_summary()
                status = HTTPStatus.OK if readiness["database"] == "ok" else HTTPStatus.SERVICE_UNAVAILABLE
                readiness["status"] = "ready" if status == HTTPStatus.OK else "not_ready"
                return self.json_response(request, readiness, status)
            if path == "/metrics":
                return self.text_response(request, self.metrics(), "text/plain; charset=utf-8")
            if path == "/api/v1/session" and method == "GET":
                return self.json_response(request, self.session(request))
            if path == "/api/v1/overview" and method == "GET":
                return self.json_response(request, self.overview())
            if path == "/api/v1/operations/database-readiness" and method == "GET":
                return self.json_response(request, self.database_readiness_summary())
            if path == "/api/v1/operations/canonicalization" and method == "GET":
                return self.json_response(request, self.canonicalization_status(parse_qs(parsed.query)))
            if path == "/api/v1/operations/canonicalization/apply" and method == "POST":
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "canonicalization apply requires admin role")
                return self.json_response(request, self.apply_canonicalization(self.apply_authenticated_actor(body, auth_context)))
            if path == "/api/v1/services" and method == "GET":
                return self.json_response(request, {"services": self.list_services()})
            if path == "/api/v1/services" and method == "POST":
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "service registration requires admin role")
                return self.json_response(request, self.create_service(self.apply_authenticated_actor(body, auth_context)), HTTPStatus.CREATED)
            if path == "/api/v1/settings/alert-channels" and method == "GET":
                return self.json_response(request, {"channels": self.list_alert_channels()})
            if path == "/api/v1/settings/alert-channels" and method == "POST":
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "alert channel changes require admin role")
                return self.json_response(request, self.create_alert_channel(self.apply_authenticated_actor(body, auth_context)), HTTPStatus.CREATED)
            if path.startswith("/api/v1/settings/alert-channels/") and method == "PATCH":
                channel_id = path.split("/")[-1]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "alert channel changes require admin role")
                return self.json_response(request, self.update_alert_channel(channel_id, self.apply_authenticated_actor(body, auth_context)))
            if path.startswith("/api/v1/settings/alert-channels/") and path.endswith("/test") and method == "POST":
                channel_id = path.split("/")[-2]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "alert channel test requires admin role")
                return self.json_response(request, self.test_alert_channel(channel_id, self.apply_authenticated_actor(body, auth_context)))
            if path.startswith("/api/v1/services/") and path.endswith("/push-credentials") and method == "GET":
                service_id = path.split("/")[-2]
                return self.json_response(request, {"credentials": self.list_push_credentials(service_id, parse_qs(parsed.query))})
            if path.startswith("/api/v1/services/") and path.endswith("/push-credentials") and method == "POST":
                service_id = path.split("/")[-2]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "push credential changes require admin role")
                return self.json_response(request, self.create_push_credential(service_id, self.apply_authenticated_actor(body, auth_context)), HTTPStatus.CREATED)
            if path.startswith("/api/v1/services/") and "/push-credentials/" in path and path.endswith("/rotate") and method == "POST":
                parts = path.split("/")
                service_id = parts[-4]
                credential_id = parts[-2]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "push credential changes require admin role")
                return self.json_response(request, self.rotate_push_credential(service_id, credential_id, self.apply_authenticated_actor(body, auth_context)), HTTPStatus.CREATED)
            if path.startswith("/api/v1/services/") and "/push-credentials/" in path and path.endswith("/revoke") and method == "POST":
                parts = path.split("/")
                service_id = parts[-4]
                credential_id = parts[-2]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "push credential changes require admin role")
                return self.json_response(request, self.revoke_push_credential(service_id, credential_id, self.apply_authenticated_actor(body, auth_context)))
            if path.startswith("/api/v1/services/") and path.endswith("/endpoint/test") and method == "POST":
                service_id = path.split("/")[-3]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "endpoint test requires admin role")
                return self.json_response(request, self.test_service_endpoint(service_id, self.apply_authenticated_actor(body, auth_context)))
            if path.startswith("/api/v1/services/") and method == "GET":
                service_id = path.split("/")[-1]
                return self.json_response(request, self.get_service_detail(service_id))
            if path == "/api/v1/advisories" and method == "GET":
                return self.json_response(request, {"advisories": self.list_advisories(parse_qs(parsed.query))})
            if path.startswith("/api/v1/advisories/") and method == "GET":
                advisory_id = unquote(path.split("/")[-1])
                return self.json_response(request, self.get_advisory(advisory_id))
            if path == "/api/v1/advisories/osv/import" and method == "POST":
                return self.json_response(request, self.import_osv_advisory(self.read_json(request)), HTTPStatus.CREATED)
            if path == "/api/v1/snapshots" and method == "POST":
                result = self.push_snapshot(
                    self.read_json(request, max_length=self.settings.max_snapshot_payload_bytes),
                    request.headers.get("Authorization"),
                )
                status = HTTPStatus.OK if result.get("idempotency_status") == "confirmed" else HTTPStatus.CREATED
                return self.json_response(
                    request,
                    result,
                    status,
                )
            if path == "/api/v1/impacts" and method == "GET":
                return self.json_response(request, self.search_impacts(parse_qs(parsed.query)))
            if path == "/api/v1/impacts/status" and method == "POST":
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_bulk_impact_status(body, auth_context)
                return self.json_response(request, self.bulk_update_impact_status(self.apply_authenticated_actor(body, auth_context)))
            if path == "/api/v1/alert-events" and method == "GET":
                return self.json_response(request, self.search_alert_events(parse_qs(parsed.query)))
            if path == "/api/v1/alerts/dispatcher/preflight" and method == "GET":
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "alert dispatcher preflight requires admin role")
                return self.json_response(request, self.alert_dispatcher_preflight(parse_qs(parsed.query)))
            if path == "/api/v1/alerts/dispatcher/activation-checklist" and method == "GET":
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "alert dispatcher activation checklist requires admin role")
                return self.json_response(request, self.alert_dispatcher_activation_checklist(parse_qs(parsed.query)))
            if path == "/api/v1/alert-events/requeue" and method == "POST":
                return self.json_response(request, self.bulk_requeue_alert_events(self.read_json(request)))
            if path == "/api/v1/alerts/daily-digest/preview" and method == "POST":
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_admin(auth_context, "daily digest preview requires admin role")
                return self.json_response(request, self.preview_daily_digest(body))
            if path == "/api/v1/audit-logs" and method == "GET":
                return self.json_response(request, self.search_audit_logs(parse_qs(parsed.query)))
            if path.startswith("/api/v1/impacts/") and method == "GET":
                impact_id = path.split("/")[-1]
                return self.json_response(request, self.get_impact(impact_id))
            if path.startswith("/api/v1/impacts/") and path.endswith("/status") and method == "PATCH":
                impact_id = path.split("/")[-2]
                body = self.read_json(request)
                auth_context = self.auth_context(request)
                self.authorize_impact_status(impact_id, body, auth_context)
                return self.json_response(request, self.update_impact_status(impact_id, self.apply_authenticated_actor(body, auth_context)))
            if path.startswith("/api/v1/alert-events/") and path.endswith("/requeue") and method == "POST":
                alert_event_id = path.split("/")[-2]
                return self.json_response(request, self.requeue_alert_event(alert_event_id, self.read_json(request)))
            if path.startswith("/api/"):
                return self.json_response(request, {"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return self.serve_static(request, path)
        except PayloadTooLargeError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        except SnapshotConflictError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.CONFLICT)
        except RateLimitError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.TOO_MANY_REQUESTS)
        except ValueError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except PermissionError as exc:
            return self.json_response(request, {"error": str(exc)}, HTTPStatus.FORBIDDEN)
        except Exception as exc:  # noqa: BLE001 - keep MVP server alive and visible.
            return self.json_response(request, {"error": "internal_error", "detail": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def read_json(self, request: BaseHTTPRequestHandler, max_length: int | None = None) -> dict:
        length = int(request.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        if max_length is not None and length > max_length:
            raise PayloadTooLargeError(f"payload exceeds maximum size of {max_length} bytes")
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
        if file_path.name == "index.html" or file_path.suffix in {".js", ".css"}:
            request.send_header("Cache-Control", "no-cache")
        else:
            request.send_header("Cache-Control", "public, max-age=31536000, immutable")
        request.end_headers()
        request.wfile.write(payload)

    def auth_context(self, request: BaseHTTPRequestHandler) -> dict:
        mode = (self.settings.auth_mode or "disabled").lower()
        if mode in {"disabled", "off", "none"}:
            return {"enabled": False, "principal": None, "roles": set(), "owner_teams": set()}
        if mode != "header":
            raise PermissionError(f"auth mode is not implemented: {mode}")
        principal = normalize_optional(request.headers.get("X-SCA-Principal"))
        if not principal:
            raise PermissionError("missing authenticated principal")
        roles = parse_csv_header(request.headers.get("X-SCA-Roles"))
        if not roles:
            raise PermissionError("missing authenticated roles")
        return {
            "enabled": True,
            "principal": principal,
            "roles": roles,
            "owner_teams": parse_csv_header(request.headers.get("X-SCA-Owner-Teams")),
        }

    def session(self, request: BaseHTTPRequestHandler) -> dict:
        mode = (self.settings.auth_mode or "disabled").lower()
        if mode in {"disabled", "off", "none"}:
            return {
                "auth_mode": "disabled",
                "authenticated": False,
                "principal": "web-console",
                "roles": ["admin", "security-approver", "service-owner"],
                "owner_teams": [],
                "capabilities": self.role_capabilities({"admin", "security-approver", "service-owner"}),
            }
        auth_context = self.auth_context(request)
        roles = auth_context["roles"]
        return {
            "auth_mode": mode,
            "authenticated": True,
            "principal": auth_context["principal"],
            "roles": sorted(roles),
            "owner_teams": sorted(auth_context["owner_teams"]),
            "capabilities": self.role_capabilities(roles),
        }

    def role_capabilities(self, roles: set[str]) -> dict:
        can_manage = "admin" in roles
        can_update_impacts = bool(roles.intersection({"admin", "security-approver", "service-owner"}))
        return {
            "manage_services": can_manage,
            "manage_credentials": can_manage,
            "manage_alert_channels": can_manage,
            "update_impacts": can_update_impacts,
            "bulk_update_impacts": can_update_impacts,
            "accept_risk": "security-approver" in roles,
        }

    def apply_authenticated_actor(self, body: dict, auth_context: dict) -> dict:
        if not auth_context.get("enabled"):
            return body
        updated = dict(body)
        updated["actor"] = auth_context["principal"]
        return updated

    def authorize_admin(self, auth_context: dict, message: str = "admin role is required") -> None:
        if not auth_context.get("enabled"):
            return
        self.require_role(auth_context, {"admin"}, message)

    def authorize_impact_status(self, impact_id: str, body: dict, auth_context: dict) -> None:
        if not auth_context.get("enabled"):
            return
        status = required(body, "status")
        if status == "accepted_risk":
            self.require_role(auth_context, {"security-approver"}, "accepted_risk requires security-approver role")
            return
        if "admin" in auth_context["roles"] or "security-approver" in auth_context["roles"]:
            return
        if status in {"acknowledged", "in_progress"} and "service-owner" in auth_context["roles"]:
            owner_team = self.impact_owner_team(impact_id)
            if owner_team in auth_context["owner_teams"]:
                return
        raise PermissionError("principal is not authorized to update this impact status")

    def authorize_bulk_impact_status(self, body: dict, auth_context: dict) -> None:
        if not auth_context.get("enabled"):
            return
        target_status = required(body, "target_status")
        roles = auth_context["roles"]
        if "admin" in roles or "security-approver" in roles:
            return
        if target_status in {"acknowledged", "in_progress"}:
            filters = body.get("filters") or {}
            owner_team = normalize_optional(filters.get("owner_team")) if isinstance(filters, dict) else None
            if "service-owner" in roles and owner_team in auth_context["owner_teams"]:
                return
        raise PermissionError("principal is not authorized to bulk update impact status")

    def require_role(self, auth_context: dict, allowed_roles: set[str], message: str) -> None:
        if not auth_context["roles"].intersection(allowed_roles):
            raise PermissionError(message)

    def impact_owner_team(self, impact_id: str) -> str | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT s.owner_team
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                WHERE i.id = ?
                """,
                (impact_id,),
            ).fetchone()
        if not row:
            raise ValueError("impact not found")
        return row["owner_team"]

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
            advisory_sync_readiness = self.advisory_sync_readiness_overview(conn)
            sla_overdue = self.sla_overdue_count(conn)
            alert_readiness = self.alert_readiness_overview(conn)
        return {
            "service_count": service_count,
            "open_impacts": open_impacts,
            "critical_impacts": critical,
            "high_impacts": high,
            "endpoint_unhealthy": unhealthy,
            "sla_overdue_impacts": sla_overdue,
            "alert_readiness": alert_readiness,
            "advisory_sync": advisory_sync,
            "advisory_sync_readiness": advisory_sync_readiness,
            "system": {"environment": self.settings.app_env},
        }

    def database_readiness_summary(self) -> dict:
        readiness = self.db.readiness()
        readiness["database_url_source"] = self.settings.database_url_source
        cutover = assess_cutover(os.environ)
        require_split_error = None
        try:
            require_split = env_flag(os.environ.get("SCA_MONITOR_POSTGRES_REQUIRE_SPLIT"), default=False)
        except ValueError as exc:
            require_split = False
            require_split_error = str(exc)
        required_cutover = assess_cutover(os.environ, require_postgres=True, require_split=require_split)
        if require_split_error:
            required_cutover = {
                **required_cutover,
                "status": "blocked",
                "checks": [
                    {
                        "id": "postgres_require_split_flag",
                        "status": "blocker",
                        "detail": f"SCA_MONITOR_POSTGRES_REQUIRE_SPLIT: {require_split_error}",
                    },
                    *required_cutover["checks"],
                ],
            }
        return {
            "status": "ready" if readiness["database"] == "ok" else "not_ready",
            **readiness,
            "cutover": cutover,
            "cutover_required": required_cutover,
            "postgres_preflight": summarize_preflight(cutover, required_cutover),
        }

    def canonicalization_status(self, query: dict[str, list[str]] | None = None) -> dict:
        query = query or {}
        limit = bounded_int(first_query_value(query, "limit"), default=100, minimum=1, maximum=1000)
        advisory_merge = self.merge_canonical_advisory_rows(limit=limit, dry_run=True)
        impact_backfill = self.backfill_canonical_impact_keys(limit=limit, dry_run=True)
        pending_advisory_merges = int(advisory_merge["candidates"])
        pending_impact_updates = int(impact_backfill["candidates"])
        status = "ready" if pending_advisory_merges == 0 and pending_impact_updates == 0 else "action_required"
        return {
            "status": status,
            "limit": limit,
            "advisory_merge": advisory_merge,
            "impact_backfill": impact_backfill,
            "pending_advisory_merges": pending_advisory_merges,
            "pending_impact_updates": pending_impact_updates,
        }

    def apply_canonicalization(self, body: dict) -> dict:
        limit = bounded_int(body.get("limit"), default=100, minimum=1, maximum=1000)
        actor = body.get("actor", "web-console")
        reason = body.get("reason", "manual canonicalization apply")
        now = utcnow()
        advisory_merge = self.merge_canonical_advisory_rows(limit=limit, dry_run=False, actor=actor)
        impact_backfill = self.backfill_canonical_impact_keys(limit=limit, dry_run=False, actor=actor)
        result = {
            "status": "ok",
            "limit": limit,
            "advisory_merge": advisory_merge,
            "impact_backfill": impact_backfill,
            "merged_advisories": advisory_merge["merged_advisories"],
            "updated_impacts": impact_backfill["updated"],
            "merged_impacts": impact_backfill["merged"],
            "actor": actor,
        }
        with self.db.connect() as conn:
            self.write_audit_log(
                conn,
                actor=actor,
                action="canonicalization.apply",
                target_type="operations",
                target_id="canonicalization",
                reason=reason,
                before=None,
                after={
                    "limit": limit,
                    "merged_advisories": result["merged_advisories"],
                    "updated_impacts": result["updated_impacts"],
                    "merged_impacts": result["merged_impacts"],
                },
                occurred_at=now,
            )
        result["readiness"] = self.canonicalization_status({"limit": [str(limit)]})
        return result

    def sla_overdue_count(self, conn) -> int:
        rows = conn.execute(
            f"""
            SELECT risk_level, status, first_detected_at
            FROM impacts
            WHERE status IN ({",".join("?" for _ in ACTIVE_IMPACT_STATUSES)})
            """,
            ACTIVE_IMPACT_STATUSES,
        ).fetchall()
        now = datetime.now(timezone.utc)
        return sum(1 for row in rows if impact_sla(row_to_dict(row), now)["overdue"])

    def advisory_sync_overview(self, conn) -> dict:
        sync = {"OSV": "seeded-demo", "CISA_KEV": "pending"}
        try:
            rows = conn.execute("SELECT source, status FROM advisory_sync_state").fetchall()
        except Exception:
            return sync
        for row in rows:
            sync[row["source"]] = row["status"]
        return sync

    def advisory_sync_readiness_overview(self, conn) -> dict:
        now = datetime.now(timezone.utc)
        rows_by_source = {}
        try:
            rows = conn.execute(
                """
                SELECT source, status, cursor, last_run_at, last_success_at, last_error_at,
                       last_error_message, imported_count, records_processed, updated_at
                FROM advisory_sync_state
                """
            ).fetchall()
        except Exception:
            rows = []
        for row in rows:
            rows_by_source[row["source"]] = row

        sources = []
        for source in INITIAL_ADVISORY_SYNC_SOURCES:
            row = rows_by_source.get(source)
            status = row["status"] if row else "pending"
            last_success_at = row["last_success_at"] if row else None
            initialized = status == "ok" and bool(last_success_at)
            lag_seconds = seconds_since(last_success_at, now)
            sources.append(
                {
                    "source": source,
                    "status": status,
                    "initialized": initialized,
                    "cursor": row["cursor"] if row else None,
                    "last_run_at": row["last_run_at"] if row else None,
                    "last_success_at": last_success_at,
                    "last_error_at": row["last_error_at"] if row else None,
                    "last_error_message": row["last_error_message"] if row else None,
                    "imported_count": int(row["imported_count"] or 0) if row else 0,
                    "records_processed": int(row["records_processed"] or 0) if row else 0,
                    "lag_seconds": lag_seconds,
                    "updated_at": row["updated_at"] if row else None,
                }
            )

        initialized_count = sum(1 for item in sources if item["initialized"])
        has_error = any(item["status"] in {"error", "partial"} for item in sources)
        if initialized_count == len(sources):
            readiness_status = "ready"
        elif has_error:
            readiness_status = "degraded"
        else:
            readiness_status = "initializing"
        return {
            "status": readiness_status,
            "required_count": len(sources),
            "initialized_count": initialized_count,
            "sources": sources,
        }

    def alert_readiness_overview(self, conn) -> dict:
        from .alert_preflight import default_channel_summary

        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM alert_events
            GROUP BY status
            """
        ).fetchall()
        counts = {row["status"]: int(row["count"]) for row in rows}
        system_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM alert_events
            WHERE impact_pk IS NULL
              AND reason LIKE 'system_%'
            GROUP BY status
            """
        ).fetchall()
        system_counts = {row["status"]: int(row["count"]) for row in system_rows}
        channel = default_channel_summary(self)
        channel_ready = bool(channel.get("configured")) and not channel.get("placeholder_target", True)
        dead_letter = counts.get("dead_letter", 0)
        system_dead_letter = system_counts.get("dead_letter", 0)
        status = "ready" if channel_ready and dead_letter == 0 else "action_required"
        return {
            "status": status,
            "default_channel_configured": bool(channel.get("configured")),
            "default_channel_placeholder": bool(channel.get("placeholder_target", True)) if channel.get("configured") else True,
            "default_channel_target_masked": channel.get("target_url_masked"),
            "pending_count": counts.get("pending", 0),
            "failed_count": counts.get("failed", 0),
            "dead_letter_count": dead_letter,
            "system_pending_count": system_counts.get("pending", 0),
            "system_failed_count": system_counts.get("failed", 0),
            "system_dead_letter_count": system_dead_letter,
        }

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
        return [sanitize_service(row_to_dict(row)) for row in rows]

    def create_service(self, body: dict) -> dict:
        service_id = required(body, "service_id")
        environment = body.get("environment", "prod")
        auth_type, auth_secret_ref, encrypted_auth_config = endpoint_auth_config_from_body(body)
        now = utcnow()
        service_pk = str(uuid.uuid4())
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO services (
                    id, service_id, service_name, environment, owner_team,
                    status_endpoint_url, collection_mode, internet_facing,
                    business_criticality, alert_channel, status_auth_type,
                    auth_secret_ref, encrypted_auth_config, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_id, environment) DO UPDATE SET
                    service_name=excluded.service_name,
                    owner_team=excluded.owner_team,
                    status_endpoint_url=COALESCE(excluded.status_endpoint_url, services.status_endpoint_url),
                    collection_mode=excluded.collection_mode,
                    internet_facing=excluded.internet_facing,
                    business_criticality=excluded.business_criticality,
                    alert_channel=excluded.alert_channel,
                    status_auth_type=COALESCE(excluded.status_auth_type, services.status_auth_type),
                    auth_secret_ref=COALESCE(excluded.auth_secret_ref, services.auth_secret_ref),
                    encrypted_auth_config=COALESCE(excluded.encrypted_auth_config, services.encrypted_auth_config),
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
                    bool(body.get("internet_facing", False)),
                    body.get("business_criticality", "medium"),
                    body.get("alert_channel", "#security-alerts"),
                    auth_type,
                    auth_secret_ref,
                    encrypted_auth_config,
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM services WHERE service_id = ? AND environment = ?", (service_id, environment)).fetchone()
            conn.execute(
                """
                INSERT INTO endpoint_health (
                    service_pk, collection_status, freshness_status, last_successful_poll_at,
                    last_error_code, last_error_message, snapshot_age_seconds, updated_at
                ) VALUES (?, 'ok', 'fresh', NULL, NULL, NULL, 0, ?)
                ON CONFLICT(service_pk) DO UPDATE SET
                    collection_status=excluded.collection_status,
                    freshness_status=excluded.freshness_status,
                    last_successful_poll_at=excluded.last_successful_poll_at,
                    last_error_code=excluded.last_error_code,
                    last_error_message=excluded.last_error_message,
                    snapshot_age_seconds=excluded.snapshot_age_seconds,
                    updated_at=excluded.updated_at
                """,
                (row["id"], now),
            )
        return {"service": sanitize_service(row_to_dict(row))}

    def list_alert_channels(self) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, channel_type, target_url, enabled, is_default, created_at, updated_at
                FROM alert_channels
                ORDER BY is_default DESC, updated_at DESC
                """
            ).fetchall()
        return [sanitize_alert_channel(row_to_dict(row)) for row in rows]

    def create_alert_channel(self, body: dict) -> dict:
        name = required(body, "name")
        channel_type = body.get("channel_type", "webhook")
        if channel_type != "webhook":
            raise ValueError("only webhook alert channels are supported")
        target_url = required(body, "target_url")
        if not target_url.startswith(("https://", "http://")):
            raise ValueError("target_url must be http or https")
        enabled = parse_bool(body.get("enabled", True))
        is_default = parse_bool(body.get("is_default", True))
        channel_id = str(uuid.uuid4())
        now = utcnow()
        with self.db.connect() as conn:
            if is_default:
                conn.execute("UPDATE alert_channels SET is_default = ?, updated_at = ?", (False, now))
            conn.execute(
                """
                INSERT INTO alert_channels (
                    id, name, channel_type, target_url, enabled, is_default, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    channel_type=excluded.channel_type,
                    target_url=excluded.target_url,
                    enabled=excluded.enabled,
                    is_default=excluded.is_default,
                    updated_at=excluded.updated_at
                """,
                (channel_id, name, channel_type, target_url, enabled, is_default, now, now),
            )
            row = conn.execute("SELECT * FROM alert_channels WHERE name = ?", (name,)).fetchone()
            self.write_audit_log(
                conn,
                actor=body.get("actor", "system"),
                action="alert_channel.upsert",
                target_type="alert_channel",
                target_id=row["id"],
                reason=body.get("reason"),
                before=None,
                after=sanitize_alert_channel(row_to_dict(row)),
                occurred_at=now,
            )
        return {"channel": sanitize_alert_channel(row_to_dict(row))}

    def update_alert_channel(self, channel_id: str, body: dict) -> dict:
        now = utcnow()
        with self.db.connect() as conn:
            current = conn.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()
            if not current:
                raise ValueError("alert channel not found")
            before = sanitize_alert_channel(row_to_dict(current))
            name = body.get("name", current["name"])
            channel_type = body.get("channel_type", current["channel_type"])
            if channel_type != "webhook":
                raise ValueError("only webhook alert channels are supported")
            target_url = body.get("target_url", current["target_url"])
            if target_url and not str(target_url).startswith(("https://", "http://")):
                raise ValueError("target_url must be http or https")
            enabled = parse_bool(body.get("enabled", current["enabled"]))
            is_default = parse_bool(body.get("is_default", current["is_default"]))
            if is_default and enabled:
                conn.execute("UPDATE alert_channels SET is_default = ?, updated_at = ? WHERE id != ?", (False, now, channel_id))
            if not enabled:
                is_default = False
            conn.execute(
                """
                UPDATE alert_channels
                SET name = ?, channel_type = ?, target_url = ?, enabled = ?, is_default = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, channel_type, target_url, enabled, is_default, now, channel_id),
            )
            row = conn.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()
            self.write_audit_log(
                conn,
                actor=body.get("actor", "system"),
                action="alert_channel.update",
                target_type="alert_channel",
                target_id=channel_id,
                reason=body.get("reason"),
                before=before,
                after=sanitize_alert_channel(row_to_dict(row)),
                occurred_at=now,
            )
        return {"channel": sanitize_alert_channel(row_to_dict(row))}

    def test_alert_channel(self, channel_id: str, body: dict, sender=None) -> dict:
        from .alert_dispatch import send_webhook

        now = utcnow()
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()
            if not row:
                raise ValueError("alert channel not found")
            before = sanitize_alert_channel(row_to_dict(row))
            if not row["enabled"]:
                raise ValueError("alert channel is disabled")
            if row["channel_type"] != "webhook":
                raise ValueError("only webhook alert channels are supported")
            payload = {
                "smoke": True,
                "smoke_id": f"alert-channel-test:{channel_id}:{now}",
                "generated_at": now,
                "channel_id": channel_id,
                "channel_name": row["name"],
                "summary": "SCA Monitor alert channel test",
                "risk_level": "info",
                "source": "sca-monitor",
            }
            headers = {
                "Idempotency-Key": payload["smoke_id"],
                "X-SCA-Alert-Channel-Test": "true",
                "X-SCA-Smoke": "true",
            }
            (sender or send_webhook)(row["target_url"], payload, headers)
            self.write_audit_log(
                conn,
                actor=body.get("actor", "system"),
                action="alert_channel.test",
                target_type="alert_channel",
                target_id=channel_id,
                reason=body.get("reason", "alert channel smoke test"),
                before=before,
                after={**before, "last_tested_at": now, "test_status": "ok"},
                occurred_at=now,
            )
        return {
            "status": "ok",
            "tested_at": now,
            "channel": before,
        }

    def default_alert_webhook_url(self) -> str | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT target_url
                FROM alert_channels
                WHERE enabled AND is_default AND channel_type = 'webhook'
                ORDER BY updated_at DESC
                LIMIT 1
                """
            ).fetchone()
        return row["target_url"] if row else None

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

    def rotate_push_credential(self, service_id: str, credential_id: str, body: dict) -> dict:
        environment = body.get("environment", "prod")
        actor = body.get("actor", "system")
        reason = body.get("reason", "push credential rotation")
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT pc.id, pc.scopes, pc.expires_at, pc.revoked_at, s.service_id, s.environment
                FROM push_credentials pc
                JOIN services s ON s.id = pc.service_pk
                WHERE pc.id = ? AND s.service_id = ? AND s.environment = ?
                """,
                (credential_id, service_id, environment),
            ).fetchone()
        if not row:
            raise ValueError("push credential not found")
        if row["revoked_at"]:
            raise ValueError("push credential already revoked")
        scopes = json.loads(row["scopes"]) if isinstance(row["scopes"], str) else row["scopes"]
        ttl_days = body.get("ttl_days")
        if ttl_days is None:
            ttl_days = remaining_ttl_days(row["expires_at"])
        revoked = self.revoke_push_credential(service_id, credential_id, {"environment": environment, "actor": actor, "reason": reason})
        issued = self.create_push_credential(
            service_id,
            {
                "environment": environment,
                "scopes": scopes,
                "ttl_days": ttl_days,
                "actor": actor,
                "reason": reason,
            },
        )
        return {
            "rotated": True,
            "service_id": service_id,
            "environment": environment,
            "revoked_credential": revoked["credential"],
            "credential": issued["credential"],
            "token": issued["token"],
            "usage": issued["usage"],
        }

    def test_service_endpoint(self, service_id: str, body: dict, fetcher=None) -> dict:
        collected = self.collect_service_endpoint_payload(service_id, body, fetcher)
        return {
            "service_id": service_id,
            "environment": collected["environment"],
            "endpoint_url": collected["endpoint_url"],
            "collection_status": "ok",
            "freshness_status": "fresh",
        }

    def collect_service_endpoint_payload(self, service_id: str, body: dict, fetcher=None) -> dict:
        environment = body.get("environment", "prod")
        with self.db.connect() as conn:
            service = conn.execute(
                """
                SELECT id, service_id, environment, status_endpoint_url, status_auth_type,
                       auth_secret_ref, encrypted_auth_config
                FROM services
                WHERE service_id = ? AND environment = ?
                """,
                (service_id, environment),
            ).fetchone()
            if not service:
                raise ValueError("service not found")
        endpoint_url = body.get("endpoint_url") or service["status_endpoint_url"]
        if not endpoint_url:
            self.record_endpoint_health(service["id"], "invalid_response", "stale", "missing_endpoint_url", "endpoint URL is not configured")
            raise ValueError("endpoint URL is not configured")
        fetcher = fetcher or fetch_json_endpoint
        try:
            payload = fetcher(endpoint_url, endpoint_auth_header(service, body))
            self.validate_endpoint_payload(payload, service_id, environment)
        except PermissionError as exc:
            self.record_endpoint_health(service["id"], "auth_failed", "stale", "auth_failed", str(exc))
            raise
        except ConnectionError as exc:
            self.record_endpoint_health(service["id"], "unreachable", "stale", "unreachable", str(exc))
            raise ValueError(f"endpoint unreachable: {exc}") from exc
        except ValueError as exc:
            self.record_endpoint_health(service["id"], "invalid_response", "stale", "invalid_response", str(exc))
            raise
        self.record_endpoint_health(service["id"], "ok", "fresh", None, None, success=True)
        return {"service_id": service_id, "environment": environment, "endpoint_url": endpoint_url, "payload": payload}

    def validate_endpoint_payload(self, payload: dict, service_id: str, environment: str) -> None:
        if not isinstance(payload, dict):
            raise ValueError("endpoint response must be a JSON object")
        if required(payload, "schema_version") != "1.0":
            raise ValueError("unsupported schema_version")
        if required(payload, "service_id") != service_id:
            raise ValueError("endpoint service_id mismatch")
        if required(payload, "environment") != environment:
            raise ValueError("endpoint environment mismatch")
        dependencies = payload.get("dependencies")
        if not isinstance(dependencies, list) or not dependencies:
            raise ValueError("dependencies required")
        for dep in dependencies:
            required(dep, "ecosystem")
            required(dep, "name")
            required(dep, "version")

    def record_endpoint_health(self, service_pk: str, collection_status: str, freshness_status: str, error_code: str | None, error_message: str | None, success: bool = False) -> None:
        now = utcnow()
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO endpoint_health (
                    service_pk, collection_status, freshness_status, last_successful_poll_at,
                    last_error_code, last_error_message, snapshot_age_seconds, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(service_pk) DO UPDATE SET
                    collection_status=excluded.collection_status,
                    freshness_status=excluded.freshness_status,
                    last_successful_poll_at=excluded.last_successful_poll_at,
                    last_error_code=excluded.last_error_code,
                    last_error_message=excluded.last_error_message,
                    updated_at=excluded.updated_at
                """,
                (service_pk, collection_status, freshness_status, now if success else None, error_code, error_message, now),
            )

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
                       is_malicious_package, published_at, modified_at, raw_payload
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
            advisory["affected_versions"] = json_column(advisory["affected_versions"], [])
            advisory["affected_ranges"] = json_column(advisory["affected_ranges"], [])
            advisory["aliases"] = advisory_aliases_for_row(advisory)
            advisory.pop("raw_payload", None)
            advisory["is_known_exploited"] = bool(advisory["is_known_exploited"])
            advisory["is_malicious_package"] = bool(advisory["is_malicious_package"])
            advisories.append(advisory)
        return advisories

    def get_advisory(self, advisory_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM advisories
                WHERE advisory_id = ? OR id = ?
                """,
                (advisory_id, advisory_id),
            ).fetchone()
            if not row:
                raise ValueError("advisory not found")
            impact_rows = conn.execute(
                """
                SELECT i.id, i.package_name, i.resolved_version, i.fixed_version, i.environment,
                       i.risk_level, i.status, i.first_detected_at, i.last_seen_at,
                       s.service_id, s.service_name, s.owner_team
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                WHERE i.advisory_pk = ?
                ORDER BY
                    CASE i.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                    i.updated_at DESC
                LIMIT 50
                """,
                (row["id"],),
            ).fetchall()
            alias_rows = conn.execute(
                """
                SELECT alias_type, alias_value
                FROM advisory_aliases
                WHERE advisory_pk = ?
                ORDER BY alias_type, alias_value
                """,
                (row["id"],),
            ).fetchall()
        advisory = row_to_dict(row)
        advisory["affected_versions"] = safe_json_loads(advisory.get("affected_versions"), [])
        advisory["affected_ranges"] = safe_json_loads(advisory.get("affected_ranges"), [])
        advisory["raw_payload"] = safe_json_loads(advisory.get("raw_payload"), {})
        advisory["aliases"] = [row_to_dict(alias) for alias in alias_rows] or advisory_aliases_for_row(advisory)
        advisory["is_known_exploited"] = bool(advisory["is_known_exploited"])
        advisory["is_malicious_package"] = bool(advisory["is_malicious_package"])
        return {
            "advisory": advisory,
            "impacts": [row_to_dict(impact) for impact in impact_rows],
        }

    def import_osv_advisory(self, body: dict) -> dict:
        advisory_id = required(body, "advisory_id")
        try:
            payload = fetch_osv_advisory(advisory_id)
            result = self.import_osv_payload(payload)
            return {"source": result["source"], "advisory_id": advisory_id, **result}
        except Exception as exc:
            self.record_advisory_sync("OSV", "error", advisory_id, str(exc))
            raise

    def import_osv_payload(self, payload: dict, source_override: str | None = None) -> dict:
        advisories = parse_osv_advisories(payload, source_override=source_override)
        source_advisory_id = str(payload.get("id") or advisories[0].advisory_id)
        sync_source = advisories[0].source
        changed_advisories: list[AdvisoryImport] = []
        rematched_impacts = 0
        with self.db.connect() as conn:
            for advisory in advisories:
                if self.upsert_advisory(conn, advisory):
                    changed_advisories.append(advisory)
            for advisory in changed_advisories:
                rematched_impacts += self.rematch_latest_snapshots_for_advisory(conn, advisory)
            self.record_advisory_sync(sync_source, "ok", source_advisory_id, None, conn=conn, imported_count=len(advisories))
        return {
            "source": sync_source,
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
            "is_known_exploited": bool(advisory.is_known_exploited),
            "is_malicious_package": bool(advisory.is_malicious_package),
            "published_at": advisory.published_at,
            "modified_at": advisory.modified_at,
            "raw_payload": json.dumps(advisory.raw_payload, ensure_ascii=False),
        }
        changed = previous is None or any(previous[key] != value for key, value in next_values.items())
        now = utcnow()
        conn.execute(
            """
            INSERT INTO advisories (
                id, advisory_id, source, summary, severity, ecosystem, package_name,
                canonical_package_name, affected_versions, affected_ranges, fixed_version,
                is_known_exploited, is_malicious_package, published_at, modified_at, first_seen_at, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                bool(advisory.is_known_exploited),
                bool(advisory.is_malicious_package),
                advisory.published_at,
                advisory.modified_at,
                now,
                json.dumps(advisory.raw_payload, ensure_ascii=False),
            ),
        )
        stored = conn.execute("SELECT id FROM advisories WHERE advisory_id = ?", (advisory.advisory_id,)).fetchone()
        if stored:
            self.replace_advisory_aliases(conn, stored["id"], advisory)
        return changed

    def replace_advisory_aliases(self, conn, advisory_pk: str, advisory: AdvisoryImport) -> None:
        aliases = advisory_aliases_for_import(advisory)
        conn.execute("DELETE FROM advisory_aliases WHERE advisory_pk = ?", (advisory_pk,))
        now = utcnow()
        for alias in aliases:
            conn.execute(
                """
                INSERT INTO advisory_aliases (id, advisory_pk, alias_type, alias_value, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(advisory_pk, alias_value) DO NOTHING
                """,
                (str(uuid.uuid4()), advisory_pk, alias["alias_type"], alias["alias_value"], now),
            )

    def rebuild_missing_advisory_aliases(self) -> int:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*
                FROM advisories a
                LEFT JOIN advisory_aliases aa ON aa.advisory_pk = a.id
                WHERE aa.id IS NULL
                """
            ).fetchall()
            for row in rows:
                advisory = advisory_import_from_row(row_to_dict(row))
                self.replace_advisory_aliases(conn, row["id"], advisory)
        return len(rows)

    def merge_canonical_advisory_rows(self, *, limit: int = 100, dry_run: bool = False, actor: str = "canonical-advisory-merge") -> dict:
        now = utcnow()
        scanned_groups = 0
        candidates = 0
        merged_advisories = 0
        items = []
        processed_groups: set[tuple[str, ...]] = set()
        with self.db.connect() as conn:
            groups = conn.execute(
                """
                SELECT aa.alias_value, a.ecosystem, a.canonical_package_name
                FROM advisory_aliases aa
                JOIN advisories a ON a.id = aa.advisory_pk
                GROUP BY aa.alias_value, a.ecosystem, a.canonical_package_name
                HAVING COUNT(DISTINCT a.id) > 1
                ORDER BY aa.alias_value ASC, a.ecosystem ASC, a.canonical_package_name ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for group in groups:
                rows = conn.execute(
                    """
                    SELECT DISTINCT a.*
                    FROM advisories a
                    JOIN advisory_aliases aa ON aa.advisory_pk = a.id
                    WHERE aa.alias_value = ?
                      AND a.ecosystem = ?
                      AND a.canonical_package_name = ?
                    ORDER BY a.advisory_id ASC
                    """,
                    (group["alias_value"], group["ecosystem"], group["canonical_package_name"]),
                ).fetchall()
                if len(rows) < 2:
                    continue
                group_key = tuple(sorted(row["id"] for row in rows))
                if group_key in processed_groups:
                    continue
                processed_groups.add(group_key)
                scanned_groups += 1
                target = min(rows, key=lambda row: (canonical_source_priority(row["source"]), row["advisory_id"]))
                sources = [row for row in rows if row["id"] != target["id"]]
                item = {
                    "alias_value": group["alias_value"],
                    "ecosystem": group["ecosystem"],
                    "canonical_package_name": group["canonical_package_name"],
                    "target_advisory_id": target["advisory_id"],
                    "target_source": target["source"],
                    "source_advisory_ids": [row["advisory_id"] for row in sources],
                    "source_count": len(sources),
                }
                items.append(item)
                candidates += len(sources)
                if dry_run:
                    continue
                for source in sources:
                    current_target = conn.execute("SELECT * FROM advisories WHERE id = ?", (target["id"],)).fetchone()
                    self.merge_advisory_row(conn, source=source, target=current_target, actor=actor, now=now)
                    merged_advisories += 1
        return {
            "status": "ok",
            "scanned_groups": scanned_groups,
            "candidates": candidates,
            "merged_advisories": 0 if dry_run else merged_advisories,
            "dry_run": dry_run,
            "items": items,
        }

    def merge_advisory_row(self, conn, *, source, target, actor: str, now: str) -> None:
        source_dict = row_to_dict(source)
        target_dict = row_to_dict(target)
        merged = merged_advisory_values(target_dict, source_dict)
        source_aliases = conn.execute(
            "SELECT alias_type, alias_value FROM advisory_aliases WHERE advisory_pk = ?",
            (source["id"],),
        ).fetchall()
        target_aliases = conn.execute(
            "SELECT alias_type, alias_value FROM advisory_aliases WHERE advisory_pk = ?",
            (target["id"],),
        ).fetchall()
        conn.execute(
            """
            UPDATE advisories
            SET severity = ?, affected_versions = ?, affected_ranges = ?, fixed_version = ?,
                is_known_exploited = ?, is_malicious_package = ?, published_at = ?,
                modified_at = ?, raw_payload = ?
            WHERE id = ?
            """,
            (
                merged["severity"],
                json.dumps(merged["affected_versions"]),
                json.dumps(merged["affected_ranges"]),
                merged["fixed_version"],
                bool(merged["is_known_exploited"]),
                bool(merged["is_malicious_package"]),
                merged["published_at"],
                merged["modified_at"],
                json.dumps(merged["raw_payload"], ensure_ascii=False),
                target["id"],
            ),
        )
        for alias in list(source_aliases) + list(target_aliases):
            conn.execute(
                """
                INSERT INTO advisory_aliases (id, advisory_pk, alias_type, alias_value, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(advisory_pk, alias_value) DO NOTHING
                """,
                (str(uuid.uuid4()), target["id"], alias["alias_type"], alias["alias_value"], now),
            )
        conn.execute("UPDATE impacts SET advisory_pk = ? WHERE advisory_pk = ?", (target["id"], source["id"]))
        conn.execute("DELETE FROM advisory_aliases WHERE advisory_pk = ?", (source["id"],))
        conn.execute("DELETE FROM advisories WHERE id = ?", (source["id"],))
        self.write_audit_log(
            conn,
            actor=actor,
            action="advisory.merge",
            target_type="advisory",
            target_id=target["advisory_id"],
            reason="canonical advisory alias merge",
            before={
                "target": {"advisory_id": target["advisory_id"], "source": target["source"]},
                "source": {"advisory_id": source["advisory_id"], "source": source["source"]},
            },
            after={
                "target_advisory_id": target["advisory_id"],
                "merged_advisory_id": source["advisory_id"],
                "severity": merged["severity"],
                "is_known_exploited": merged["is_known_exploited"],
                "is_malicious_package": merged["is_malicious_package"],
            },
            occurred_at=now,
        )

    def rematch_latest_snapshots_for_advisory(self, conn, advisory: AdvisoryImport) -> int:
        rows = conn.execute(
            """
            SELECT DISTINCT ds.service_pk, ds.id AS snapshot_pk
            FROM dependency_snapshots ds
            JOIN dependencies d ON d.snapshot_pk = ds.id
            WHERE ds.is_latest
              AND d.ecosystem = ?
              AND d.canonical_package_name = ?
            """,
            (advisory.ecosystem, advisory.canonical_package_name),
        ).fetchall()
        count = 0
        for row in rows:
            count += self.match_impacts(conn, row["service_pk"], row["snapshot_pk"])
        return count

    def enrich_known_exploited_advisories(self, conn, cve_id: str) -> dict:
        cve = normalize_cve_id(cve_id)
        if not cve:
            raise ValueError("cve_id required")
        enriched = 0
        rematched = 0
        rows = conn.execute("SELECT * FROM advisories WHERE source != 'CISA_KEV'").fetchall()
        for row in rows:
            aliases = advisory_alias_values(row_to_dict(row))
            if cve not in aliases:
                continue
            if row["is_known_exploited"] and row["severity"] == "critical":
                continue
            conn.execute(
                """
                UPDATE advisories
                SET is_known_exploited = ?,
                    severity = 'critical'
                WHERE id = ?
                """,
                (True, row["id"]),
            )
            updated = conn.execute("SELECT * FROM advisories WHERE id = ?", (row["id"],)).fetchone()
            enriched += 1
            rematched += self.rematch_latest_snapshots_for_advisory(conn, advisory_import_from_row(row_to_dict(updated)))
        return {"enriched_advisories": enriched, "rematched_impacts": rematched}

    def enrich_nvd_advisories(self, conn, nvd_advisory: AdvisoryImport) -> dict:
        cve = normalize_cve_id(nvd_advisory.advisory_id)
        if not cve:
            raise ValueError("nvd_advisory must have a CVE advisory_id")
        enriched = 0
        rematched = 0
        rows = conn.execute("SELECT * FROM advisories WHERE source != 'NVD'").fetchall()
        cpe_matches = [
            item
            for item in nvd_advisory.affected_ranges
            if isinstance(item, dict) and item.get("criteria")
        ]
        for row in rows:
            row_dict = row_to_dict(row)
            aliases = advisory_alias_values(row_dict)
            if cve not in aliases:
                continue
            raw_payload = json_column(row["raw_payload"], {})
            if not isinstance(raw_payload, dict):
                raw_payload = {"value": raw_payload}
            enrichment = {
                "cve_id": cve,
                "severity": nvd_advisory.severity,
                "published_at": nvd_advisory.published_at,
                "modified_at": nvd_advisory.modified_at,
                "cpe_matches": cpe_matches,
                "cwes": nvd_cwes(nvd_advisory.raw_payload),
                "references": nvd_references(nvd_advisory.raw_payload),
                "raw_payload": nvd_advisory.raw_payload,
            }
            next_severity = highest_risk(row["severity"], nvd_advisory.severity)
            if raw_payload.get("_nvd_enrichment") == enrichment and row["severity"] == next_severity:
                continue
            raw_payload["_nvd_enrichment"] = enrichment
            conn.execute(
                """
                UPDATE advisories
                SET severity = ?,
                    modified_at = ?,
                    raw_payload = ?
                WHERE id = ?
                """,
                (
                    next_severity,
                    max_optional_text(row["modified_at"], nvd_advisory.modified_at),
                    json.dumps(raw_payload, ensure_ascii=False),
                    row["id"],
                ),
            )
            updated = conn.execute("SELECT * FROM advisories WHERE id = ?", (row["id"],)).fetchone()
            enriched += 1
            rematched += self.rematch_latest_snapshots_for_advisory(conn, advisory_import_from_row(row_to_dict(updated)))
        return {"enriched_advisories": enriched, "rematched_impacts": rematched}

    def record_advisory_sync(
        self,
        source: str,
        status: str,
        advisory_id: str | None,
        error_message: str | None,
        conn=None,
        imported_count: int = 0,
        cursor: str | None = None,
        records_processed: int | None = None,
    ) -> None:
        now = utcnow()
        next_cursor = cursor if status == "ok" else None
        processed_count = imported_count if records_processed is None else records_processed

        def write(connection) -> None:
            connection.execute(
                """
                INSERT INTO advisory_sync_state (
                    source, status, cursor, last_run_at, last_success_at, last_error_at,
                    last_error_message, last_advisory_id, imported_count, records_processed, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    status=excluded.status,
                    cursor=COALESCE(excluded.cursor, advisory_sync_state.cursor),
                    last_run_at=excluded.last_run_at,
                    last_success_at=COALESCE(excluded.last_success_at, advisory_sync_state.last_success_at),
                    last_error_at=COALESCE(excluded.last_error_at, advisory_sync_state.last_error_at),
                    last_error_message=excluded.last_error_message,
                    last_advisory_id=excluded.last_advisory_id,
                    imported_count=advisory_sync_state.imported_count + excluded.imported_count,
                    records_processed=excluded.records_processed,
                    updated_at=excluded.updated_at
                """,
                (
                    source,
                    status,
                    next_cursor,
                    now,
                    now if status == "ok" else None,
                    now if status != "ok" else None,
                    error_message,
                    advisory_id,
                    imported_count,
                    processed_count,
                    now,
                ),
            )
            if status != "ok":
                self.enqueue_advisory_sync_failure_alert(
                    connection,
                    source=source,
                    advisory_id=advisory_id,
                    error_message=error_message,
                    occurred_at=now,
                )
            else:
                self.resolve_advisory_sync_failure_alert(connection, source=source, resolved_at=now)

        if conn is not None:
            write(conn)
            return
        with self.db.connect() as connection:
            write(connection)

    def enqueue_advisory_sync_failure_alert(
        self,
        conn,
        *,
        source: str,
        advisory_id: str | None,
        error_message: str | None,
        occurred_at: str,
    ) -> None:
        suppression_key = f"system:advisory_sync:{source}:failed"
        existing = conn.execute(
            """
            SELECT id
            FROM alert_events
            WHERE reason = 'system_advisory_sync_failed'
              AND alert_suppression_key = ?
              AND status IN ('pending', 'failed', 'dispatching')
            LIMIT 1
            """,
            (suppression_key,),
        ).fetchone()
        if existing:
            return
        payload = {
            "alert_type": "system",
            "source": source,
            "advisory_id": advisory_id,
            "error_message": error_message,
            "occurred_at": occurred_at,
        }
        conn.execute(
            """
            INSERT INTO alert_events (id, impact_pk, alert_suppression_key, reason, status, payload, created_at)
            VALUES (?, NULL, ?, 'system_advisory_sync_failed', 'pending', ?, ?)
            """,
            (str(uuid.uuid4()), suppression_key, json.dumps(payload, ensure_ascii=False), occurred_at),
        )

    def resolve_advisory_sync_failure_alert(self, conn, *, source: str, resolved_at: str) -> None:
        suppression_key = f"system:advisory_sync:{source}:failed"
        rows = conn.execute(
            """
            SELECT id, payload
            FROM alert_events
            WHERE reason = 'system_advisory_sync_failed'
              AND alert_suppression_key = ?
              AND status IN ('pending', 'failed', 'dispatching')
            """,
            (suppression_key,),
        ).fetchall()
        for row in rows:
            payload = parse_json_field(row["payload"])
            if not isinstance(payload, dict):
                payload = {}
            payload.update({"resolved_at": resolved_at, "resolved_by_status": "ok"})
            conn.execute(
                """
                UPDATE alert_events
                SET status = 'resolved',
                    payload = ?,
                    next_attempt_at = NULL,
                    dispatch_lock_owner = NULL,
                    dispatch_lock_expires_at = NULL
                WHERE id = ?
                """,
                (json.dumps(payload, ensure_ascii=False), row["id"]),
            )

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
                conn.execute(
                    """
                    UPDATE advisory_sync_state
                    SET lease_acquire_failures = lease_acquire_failures + 1,
                        last_error_at = ?,
                        last_error_message = ?,
                        updated_at = ?
                    WHERE source = ?
                    """,
                    (
                        now,
                        f"lock held by {row['lock_owner']} until {row['lock_expires_at']}",
                        now,
                        source,
                    ),
                )
                conn.commit()
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
            service = conn.execute(
                """
                SELECT s.*, eh.collection_status, eh.freshness_status, eh.last_successful_poll_at,
                       eh.last_error_code, eh.last_error_message, eh.snapshot_age_seconds
                FROM services s
                LEFT JOIN endpoint_health eh ON eh.service_pk = s.id
                WHERE s.service_id = ?
                ORDER BY s.updated_at DESC
                LIMIT 1
                """,
                (service_id,),
            ).fetchone()
            if not service:
                raise ValueError("service not found")
            snapshot = conn.execute(
                """
                SELECT id, snapshot_id, schema_version, environment, generated_at, collected_at,
                       source_type, freshness_status, content_hash, artifact_type, artifact_name,
                       artifact_digest
                FROM dependency_snapshots
                WHERE id = ?
                """,
                (service["latest_snapshot_id"],),
            ).fetchone() if service["latest_snapshot_id"] else None
            dependencies = conn.execute(
                """
                SELECT ecosystem, package_name, canonical_package_name, resolved_version,
                       package_url, dependency_scope, direct_dependency, source
                FROM dependencies
                WHERE snapshot_pk = ?
                ORDER BY ecosystem, canonical_package_name, resolved_version
                LIMIT 200
                """,
                (snapshot["id"],),
            ).fetchall() if snapshot else []
            dependency_summary = conn.execute(
                """
                SELECT ecosystem, COUNT(*) AS count
                FROM dependencies
                WHERE snapshot_pk = ?
                GROUP BY ecosystem
                ORDER BY ecosystem
                """,
                (snapshot["id"],),
            ).fetchall() if snapshot else []
            impacts = conn.execute(
                """
                SELECT i.id, i.package_name, i.resolved_version, i.fixed_version, i.risk_level,
                       i.risk_reason, i.status, i.first_detected_at, i.last_seen_at,
                       i.freshness_status, i.alert_suppression_key, i.updated_at,
                       a.advisory_id, a.source, a.summary, a.is_known_exploited, a.is_malicious_package
                FROM impacts i
                JOIN advisories a ON a.id = i.advisory_pk
                WHERE i.service_pk = ?
                ORDER BY i.updated_at DESC
                """,
                (service["id"],),
            ).fetchall()
        return {
            "service": sanitize_service(row_to_dict(service)),
            "latest_snapshot": row_to_dict(snapshot),
            "dependency_summary": [row_to_dict(row) for row in dependency_summary],
            "dependencies": [sanitize_dependency(row_to_dict(row)) for row in dependencies],
            "impacts": [sanitize_service_impact(row_to_dict(row)) for row in impacts],
        }

    def push_snapshot(self, body: dict, authorization: str | None = None) -> dict:
        service_id = required(body, "service_id")
        environment = body.get("environment", "prod")
        dependencies = body.get("dependencies") or []
        if not dependencies:
            raise ValueError("dependencies required")
        if not isinstance(dependencies, list):
            raise ValueError("dependencies must be a list")
        if len(dependencies) > self.settings.max_snapshot_dependencies:
            raise ValueError(f"dependencies exceed maximum count of {self.settings.max_snapshot_dependencies}")
        credential_id = None
        if authorization:
            credential_id = self.validate_push_authorization(authorization, service_id, environment)
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
            rate_limit_key = f"push_credential:{credential_id}" if credential_id else f"service:{service['id']}"
            self.enforce_snapshot_push_rate_limit(conn, rate_limit_key, now)
            existing = conn.execute(
                "SELECT id, content_hash FROM dependency_snapshots WHERE service_pk = ? AND snapshot_id = ?",
                (service["id"], snapshot_id),
            ).fetchone()
            if existing:
                snapshot_pk = existing["id"]
                if existing["content_hash"] != content_hash:
                    raise SnapshotConflictError("snapshot_id already exists with different content_hash")
                conn.execute(
                    "UPDATE dependency_snapshots SET last_confirmed_at = ? WHERE id = ?",
                    (now, snapshot_pk),
                )
                conn.execute("UPDATE services SET updated_at = ? WHERE id = ?", (now, service["id"]))
                return {
                    "snapshot_id": snapshot_id,
                    "content_hash": content_hash,
                    "impacts_created_or_updated": 0,
                    "idempotency_status": "confirmed",
                }
            else:
                conn.execute("UPDATE dependency_snapshots SET is_latest = ? WHERE service_pk = ?", (False, service["id"]))
                conn.execute(
                    """
                    INSERT INTO dependency_snapshots (
                        id, snapshot_id, service_pk, schema_version, environment, generated_at,
                        collected_at, source_type, freshness_status, content_hash, is_latest,
                        artifact_type, artifact_name, artifact_digest, raw_payload, last_confirmed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'push', 'fresh', ?, ?, ?, ?, ?, ?, ?)
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
                        True,
                        artifact.get("type"),
                        artifact.get("name"),
                        artifact.get("digest"),
                        json.dumps(body, ensure_ascii=False),
                        now,
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
                            bool(dep.get("direct", False)),
                            json.dumps(dep.get("dependency_path", [])),
                            dep.get("source"),
                            now,
                        ),
                    )
            impacts = self.match_impacts(conn, service["id"], snapshot_pk)
        return {
            "snapshot_id": snapshot_id,
            "content_hash": content_hash,
            "impacts_created_or_updated": impacts,
            "idempotency_status": "created",
        }

    def enforce_snapshot_push_rate_limit(self, conn, rate_limit_key: str, now: str) -> None:
        limit = self.settings.max_snapshot_pushes_per_minute
        if limit <= 0:
            return
        window_start = datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat()
        row = conn.execute(
            "SELECT window_start, request_count FROM snapshot_push_rate_limits WHERE rate_limit_key = ?",
            (rate_limit_key,),
        ).fetchone()
        if not row or row["window_start"] != window_start:
            conn.execute(
                """
                INSERT INTO snapshot_push_rate_limits (rate_limit_key, window_start, request_count, updated_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(rate_limit_key) DO UPDATE SET
                    window_start = excluded.window_start,
                    request_count = excluded.request_count,
                    updated_at = excluded.updated_at
                """,
                (rate_limit_key, window_start, now),
            )
            return
        if row["request_count"] >= limit:
            raise RateLimitError(f"snapshot push rate limit exceeded: {limit} requests per minute")
        conn.execute(
            """
            UPDATE snapshot_push_rate_limits
            SET request_count = request_count + 1, updated_at = ?
            WHERE rate_limit_key = ?
            """,
            (now, rate_limit_key),
        )

    def validate_push_authorization(self, authorization: str, service_id: str, environment: str) -> str:
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
            scopes = json_column(row["scopes"], [])
            if "snapshot:push" not in scopes:
                raise PermissionError("push credential lacks snapshot:push scope")
            if row["service_id"] != service_id or row["environment"] != environment:
                raise PermissionError("push credential is not bound to this service environment")
            conn.execute("UPDATE push_credentials SET last_used_at = ? WHERE id = ?", (now, row["id"]))
            return row["id"]

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
                affected_versions = json_column(adv["affected_versions"], [])
                affected_ranges = json_column(adv["affected_ranges"], [])
                if not version_is_affected(dep["resolved_version"], affected_versions, affected_ranges):
                    continue
                risk = "critical" if adv["is_malicious_package"] or adv["is_known_exploited"] or adv["severity"] == "critical" else adv["severity"]
                canonical_advisory_key = self.canonical_advisory_key(conn, adv)
                identity = ":".join([service["service_id"], service["environment"], canonical_advisory_key, dep["canonical_package_name"]])
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

    def canonical_advisory_key(self, conn, advisory_row) -> str:
        aliases = conn.execute(
            """
            SELECT alias_value
            FROM advisory_aliases
            WHERE advisory_pk = ?
            """,
            (advisory_row["id"],),
        ).fetchall()
        alias_values = [row["alias_value"] for row in aliases]
        if not alias_values:
            return advisory_row["advisory_id"]
        placeholders = ", ".join("?" for _ in alias_values)
        candidates = conn.execute(
            f"""
            SELECT DISTINCT a.advisory_id, a.source
            FROM advisories a
            JOIN advisory_aliases aa ON aa.advisory_pk = a.id
            WHERE aa.alias_value IN ({placeholders})
              AND a.ecosystem = ?
              AND a.canonical_package_name = ?
            """,
            (*alias_values, advisory_row["ecosystem"], advisory_row["canonical_package_name"]),
        ).fetchall()
        if not candidates:
            return advisory_row["advisory_id"]
        best = min(
            candidates,
            key=lambda row: (canonical_source_priority(row["source"]), row["advisory_id"]),
        )
        return best["advisory_id"]

    def backfill_canonical_impact_keys(self, *, limit: int = 100, dry_run: bool = False, actor: str = "canonical-backfill") -> dict:
        now = utcnow()
        scanned = 0
        candidates = 0
        updated = 0
        merged = 0
        conflicts = 0
        unchanged = 0
        items = []
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT i.id, i.impact_identity, i.alert_suppression_key, i.risk_level,
                       i.canonical_package_name, s.service_id, s.environment,
                       a.id AS advisory_pk, a.advisory_id, a.source, a.ecosystem,
                       a.canonical_package_name AS advisory_canonical_package_name
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                JOIN advisories a ON a.id = i.advisory_pk
                ORDER BY i.updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for row in rows:
                scanned += 1
                advisory_row = {
                    "id": row["advisory_pk"],
                    "advisory_id": row["advisory_id"],
                    "source": row["source"],
                    "ecosystem": row["ecosystem"],
                    "canonical_package_name": row["advisory_canonical_package_name"],
                }
                canonical_key = self.canonical_advisory_key(conn, advisory_row)
                next_identity = ":".join([row["service_id"], row["environment"], canonical_key, row["canonical_package_name"]])
                next_alert_key = ":".join([next_identity, row["risk_level"], "open"])
                if row["impact_identity"] == next_identity and row["alert_suppression_key"] == next_alert_key:
                    unchanged += 1
                    continue
                candidates += 1
                conflict = conn.execute(
                    "SELECT id FROM impacts WHERE impact_identity = ? AND id != ?",
                    (next_identity, row["id"]),
                ).fetchone()
                item = {
                    "impact_id": row["id"],
                    "from_identity": row["impact_identity"],
                    "to_identity": next_identity,
                    "from_alert_suppression_key": row["alert_suppression_key"],
                    "to_alert_suppression_key": next_alert_key,
                    "conflict_impact_id": conflict["id"] if conflict else None,
                    "action": "merge" if conflict else "update",
                }
                items.append(item)
                if conflict:
                    if dry_run:
                        continue
                    self.merge_canonical_impact_conflict(
                        conn,
                        source_impact_id=row["id"],
                        target_impact_id=conflict["id"],
                        canonical_identity=next_identity,
                        actor=actor,
                        now=now,
                    )
                    merged += 1
                    continue
                if dry_run:
                    continue
                conn.execute(
                    """
                    UPDATE impacts
                    SET impact_identity = ?, alert_suppression_key = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (next_identity, next_alert_key, now, row["id"]),
                )
                conn.execute(
                    """
                    UPDATE alert_events
                    SET alert_suppression_key = ?
                    WHERE impact_pk = ? AND alert_suppression_key = ?
                    """,
                    (next_alert_key, row["id"], row["alert_suppression_key"]),
                )
                conn.execute(
                    """
                    INSERT INTO impact_history (id, impact_pk, from_status, to_status, actor, reason, created_at)
                    VALUES (?, ?, NULL, 'open', ?, ?, ?)
                    """,
                    (str(uuid.uuid4()), row["id"], actor, "canonical impact key backfill", now),
                )
                updated += 1
        return {
            "status": "ok" if conflicts == 0 else "partial",
            "scanned": scanned,
            "candidates": candidates,
            "updated": 0 if dry_run else updated,
            "merged": 0 if dry_run else merged,
            "conflicts": conflicts,
            "unchanged": unchanged,
            "dry_run": dry_run,
            "items": items,
        }

    def merge_canonical_impact_conflict(
        self,
        conn,
        *,
        source_impact_id: str,
        target_impact_id: str,
        canonical_identity: str,
        actor: str,
        now: str,
    ) -> None:
        source = conn.execute("SELECT * FROM impacts WHERE id = ?", (source_impact_id,)).fetchone()
        target = conn.execute("SELECT * FROM impacts WHERE id = ?", (target_impact_id,)).fetchone()
        if not source or not target:
            raise ValueError("source and target impacts are required for canonical merge")

        source_dict = row_to_dict(source)
        target_dict = row_to_dict(target)
        current_row = source_dict if str(source_dict["last_seen_at"]) > str(target_dict["last_seen_at"]) else target_dict
        risk_row = self.higher_risk_impact(source_dict, target_dict)
        merged_risk = risk_row["risk_level"]
        merged_alert_key = ":".join([canonical_identity, merged_risk, "open"])
        merged_status = self.merge_impact_status(source_dict["status"], target_dict["status"])
        first_detected_at = min(str(source_dict["first_detected_at"]), str(target_dict["first_detected_at"]))
        last_seen_at = max(str(source_dict["last_seen_at"]), str(target_dict["last_seen_at"]))

        target_active = conn.execute(
            "SELECT id FROM accepted_risks WHERE impact_pk = ? AND revoked_at IS NULL",
            (target_impact_id,),
        ).fetchone()
        source_active = conn.execute(
            "SELECT id FROM accepted_risks WHERE impact_pk = ? AND revoked_at IS NULL",
            (source_impact_id,),
        ).fetchone()
        if target_active and source_active:
            conn.execute("UPDATE accepted_risks SET revoked_at = ? WHERE id = ?", (now, source_active["id"]))

        conn.execute("UPDATE accepted_risks SET impact_pk = ? WHERE impact_pk = ?", (target_impact_id, source_impact_id))
        conn.execute("UPDATE impact_history SET impact_pk = ? WHERE impact_pk = ?", (target_impact_id, source_impact_id))
        conn.execute("UPDATE alert_events SET impact_pk = ? WHERE impact_pk = ?", (target_impact_id, source_impact_id))
        conn.execute(
            """
            UPDATE alert_events
            SET alert_suppression_key = ?
            WHERE impact_pk = ?
              AND alert_suppression_key IN (?, ?)
            """,
            (merged_alert_key, target_impact_id, source_dict["alert_suppression_key"], target_dict["alert_suppression_key"]),
        )
        conn.execute(
            """
            UPDATE impacts
            SET dependency_pk = ?, snapshot_pk = ?, resolved_version = ?, fixed_version = ?,
                risk_level = ?, risk_reason = ?, status = ?, first_detected_at = ?,
                last_seen_at = ?, resolved_at = NULL, freshness_status = ?, artifact_digest = ?,
                impact_identity = ?, alert_suppression_key = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                current_row["dependency_pk"],
                current_row["snapshot_pk"],
                current_row["resolved_version"],
                current_row["fixed_version"],
                merged_risk,
                risk_row["risk_reason"],
                merged_status,
                first_detected_at,
                last_seen_at,
                current_row["freshness_status"],
                current_row["artifact_digest"],
                canonical_identity,
                merged_alert_key,
                now,
                target_impact_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO impact_history (id, impact_pk, from_status, to_status, actor, reason, created_at)
            VALUES (?, ?, NULL, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                target_impact_id,
                merged_status,
                actor,
                f"canonical impact merge from {source_impact_id}",
                now,
            ),
        )
        conn.execute("DELETE FROM impacts WHERE id = ?", (source_impact_id,))

    @staticmethod
    def higher_risk_impact(left: dict, right: dict) -> dict:
        left_rank = RISK_RANK.get(str(left.get("risk_level") or "info").lower(), RISK_RANK["info"])
        right_rank = RISK_RANK.get(str(right.get("risk_level") or "info").lower(), RISK_RANK["info"])
        return left if left_rank < right_rank else right

    @staticmethod
    def merge_impact_status(source_status: str, target_status: str) -> str:
        if target_status in ACTIVE_IMPACT_STATUSES:
            return target_status
        if source_status in ACTIVE_IMPACT_STATUSES:
            return source_status
        return target_status

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
        if known_exploited := query.get("known_exploited", [None])[0]:
            where.append("a.is_known_exploited = ?")
            params.append(str(known_exploited).lower() in {"1", "true", "yes"})
        if malicious_package := query.get("malicious_package", [None])[0]:
            where.append("a.is_malicious_package = ?")
            params.append(str(malicious_package).lower() in {"1", "true", "yes"})
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
                SELECT i.*, s.service_id, s.service_name, a.advisory_id, a.summary,
                       a.is_known_exploited, a.is_malicious_package
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
            "impacts": [sanitize_service_impact(row_to_dict(row)) for row in rows],
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
            accepted_risk = conn.execute(
                """
                SELECT id, approved_by, reason, expires_at, revoked_at, created_at
                FROM accepted_risks
                WHERE impact_pk = ? AND revoked_at IS NULL
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (impact_id,),
            ).fetchone()
        if not row:
            raise ValueError("impact not found")
        impact = row_to_dict(row)
        impact["affected_versions"] = json_column(impact["affected_versions"], [])
        impact["affected_ranges"] = json_column(impact["affected_ranges"], [])
        impact = enrich_impact_sla(impact)
        return {
            "impact": impact,
            "history": [row_to_dict(history) for history in history_rows],
            "accepted_risk": row_to_dict(accepted_risk),
        }

    def search_alert_events(self, query: dict[str, list[str]]) -> dict:
        where = []
        params = []
        if status := query.get("status", [None])[0]:
            where.append("ae.status = ?")
            params.append(status)
        if parse_bool(query.get("system_only", [None])[0]):
            where.append("ae.impact_pk IS NULL AND ae.reason LIKE 'system_%'")
        if search := query.get("q", [None])[0]:
            like = f"%{search.lower()}%"
            where.append(
                """
                (
                    lower(ae.id) LIKE ?
                    OR lower(ae.reason) LIKE ?
                    OR lower(ae.alert_suppression_key) LIKE ?
                    OR lower(s.service_id) LIKE ?
                    OR lower(i.package_name) LIKE ?
                    OR lower(a.advisory_id) LIKE ?
                )
                """
            )
            params.extend([like] * 6)
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        limit = bounded_int(query.get("limit", [None])[0], default=20, minimum=1, maximum=100)
        offset = bounded_int(query.get("offset", [None])[0], default=0, minimum=0, maximum=1_000_000)
        with self.db.connect() as conn:
            total = conn.execute(
                f"""
                SELECT COUNT(*) AS c
                FROM alert_events ae
                LEFT JOIN impacts i ON i.id = ae.impact_pk
                LEFT JOIN services s ON s.id = i.service_pk
                LEFT JOIN advisories a ON a.id = i.advisory_pk
                {sql_where}
                """,
                tuple(params),
            ).fetchone()["c"]
            rows = conn.execute(
                f"""
                SELECT ae.id, ae.impact_pk, ae.alert_suppression_key, ae.reason, ae.status,
                       ae.channel_type, ae.channel_target, ae.sent_at, ae.created_at,
                       ae.retry_count, ae.next_attempt_at, ae.payload,
                       s.service_id, s.service_name, i.package_name, i.resolved_version,
                       i.risk_level, a.advisory_id, a.summary
                FROM alert_events ae
                LEFT JOIN impacts i ON i.id = ae.impact_pk
                LEFT JOIN services s ON s.id = i.service_pk
                LEFT JOIN advisories a ON a.id = i.advisory_pk
                {sql_where}
                ORDER BY ae.created_at DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params + [limit, offset]),
            ).fetchall()
        events = []
        for row in rows:
            event = row_to_dict(row)
            event["channel_target_masked"] = mask_url(event.pop("channel_target", None))
            event["payload"] = json_column(event.get("payload"), {})
            events.append(event)
        return {
            "alert_events": events,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "returned": len(events),
                "next_offset": offset + limit if offset + limit < total else None,
                "prev_offset": max(offset - limit, 0) if offset > 0 else None,
            },
        }

    def update_impact_status(self, impact_id: str, body: dict) -> dict:
        status = required(body, "status")
        if status not in IMPACT_STATUSES:
            raise ValueError(f"status must be one of {', '.join(sorted(IMPACT_STATUSES))}")
        reason = body.get("reason")
        actor = body.get("actor", "system")
        if status == "accepted_risk":
            if not normalize_optional(reason):
                raise ValueError("reason is required for accepted_risk")
            if not normalize_optional(body.get("expires_at")):
                raise ValueError("expires_at is required for accepted_risk")
        now = utcnow()
        with self.db.connect() as conn:
            current = conn.execute("SELECT id, status, risk_level, package_name, resolved_version FROM impacts WHERE id = ?", (impact_id,)).fetchone()
            if not current:
                raise ValueError("impact not found")
            conn.execute("UPDATE impacts SET status = ?, resolved_at = CASE WHEN ? = 'fixed' THEN ? ELSE resolved_at END, updated_at = ? WHERE id = ?", (status, status, now, now, impact_id))
            accepted_risk = None
            if status == "accepted_risk":
                accepted_risk = self.record_accepted_risk(conn, impact_id, actor, reason, body["expires_at"], now)
            elif current["status"] == "accepted_risk":
                self.revoke_active_accepted_risk(conn, impact_id, now)
            conn.execute(
                "INSERT INTO impact_history (id, impact_pk, from_status, to_status, actor, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), impact_id, current["status"], status, actor, reason, now),
            )
            updated = conn.execute("SELECT id, status, risk_level, package_name, resolved_version FROM impacts WHERE id = ?", (impact_id,)).fetchone()
            self.write_audit_log(
                conn,
                actor=actor,
                action="impact.status.update",
                target_type="impact",
                target_id=impact_id,
                reason=reason,
                before=row_to_dict(current),
                after=row_to_dict(updated),
                occurred_at=now,
            )
        return {"impact_id": impact_id, "status": status, "accepted_risk": accepted_risk}

    def bulk_update_impact_status(self, body: dict) -> dict:
        target_status = required(body, "target_status")
        if target_status not in BULK_IMPACT_TARGET_STATUSES:
            raise ValueError(f"target_status must be one of {', '.join(sorted(BULK_IMPACT_TARGET_STATUSES))}")
        filters = body.get("filters") or {}
        if not isinstance(filters, dict):
            raise ValueError("filters must be an object")
        limit = bounded_int(body.get("limit"), default=100, minimum=1, maximum=200)
        query = {key: [str(value)] for key, value in filters.items() if value is not None and str(value).strip()}
        query["limit"] = [str(limit)]
        query["offset"] = ["0"]
        page = self.search_impacts(query)
        updated = []
        skipped = []
        for impact in page["impacts"]:
            if impact["status"] == target_status:
                skipped.append({"impact_id": impact["id"], "status": impact["status"], "reason": "already_target_status"})
                continue
            result = self.update_impact_status(
                impact["id"],
                {
                    "status": target_status,
                    "actor": body.get("actor", "operator"),
                    "reason": body.get("reason", "bulk impact status update"),
                },
            )
            updated.append(result)
        return {
            "matched": page["pagination"]["total"],
            "limit": limit,
            "updated": len(updated),
            "skipped": len(skipped),
            "target_status": target_status,
            "impacts": updated,
            "skipped_impacts": skipped,
        }

    def record_accepted_risk(self, conn, impact_id: str, approved_by: str, reason: str, expires_at: str, created_at: str) -> dict:
        self.revoke_active_accepted_risk(conn, impact_id, created_at)
        accepted_risk_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO accepted_risks (
                id, impact_pk, approved_by, reason, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (accepted_risk_id, impact_id, approved_by, reason, expires_at, created_at),
        )
        row = conn.execute(
            """
            SELECT id, approved_by, reason, expires_at, revoked_at, created_at
            FROM accepted_risks
            WHERE id = ?
            """,
            (accepted_risk_id,),
        ).fetchone()
        return row_to_dict(row)

    def revoke_active_accepted_risk(self, conn, impact_id: str, revoked_at: str) -> None:
        conn.execute(
            """
            UPDATE accepted_risks
            SET revoked_at = ?
            WHERE impact_pk = ? AND revoked_at IS NULL
            """,
            (revoked_at, impact_id),
        )

    def expire_accepted_risks(self, *, now: str | None = None, limit: int = 100, dry_run: bool = False, actor: str = "system") -> dict:
        checked_at = now or utcnow()
        limit = bounded_int(limit, default=100, minimum=1, maximum=1000)
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT ar.id AS accepted_risk_id, ar.impact_pk, ar.approved_by, ar.reason,
                       ar.expires_at, i.status, i.risk_level, i.package_name, i.resolved_version
                FROM accepted_risks ar
                JOIN impacts i ON i.id = ar.impact_pk
                WHERE ar.revoked_at IS NULL
                  AND i.status = 'accepted_risk'
                ORDER BY ar.expires_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            expired_rows = [row for row in rows if timestamp_is_due(row["expires_at"], checked_at)]
            if dry_run:
                return {
                    "checked_at": checked_at,
                    "matched": len(rows),
                    "expired": len(expired_rows),
                    "dry_run": True,
                    "impact_ids": [row["impact_pk"] for row in expired_rows],
                }
            expired = []
            for row in expired_rows:
                impact_id = row["impact_pk"]
                before = {
                    "id": impact_id,
                    "status": row["status"],
                    "risk_level": row["risk_level"],
                    "package_name": row["package_name"],
                    "resolved_version": row["resolved_version"],
                    "accepted_risk_id": row["accepted_risk_id"],
                    "expires_at": row["expires_at"],
                }
                conn.execute(
                    """
                    UPDATE impacts
                    SET status = 'open', updated_at = ?
                    WHERE id = ?
                    """,
                    (checked_at, impact_id),
                )
                self.revoke_active_accepted_risk(conn, impact_id, checked_at)
                conn.execute(
                    """
                    INSERT INTO impact_history (id, impact_pk, from_status, to_status, actor, reason, created_at)
                    VALUES (?, ?, 'accepted_risk', 'open', ?, ?, ?)
                    """,
                    (str(uuid.uuid4()), impact_id, actor, "accepted risk expired", checked_at),
                )
                updated = conn.execute(
                    "SELECT id, status, risk_level, package_name, resolved_version FROM impacts WHERE id = ?",
                    (impact_id,),
                ).fetchone()
                self.write_audit_log(
                    conn,
                    actor=actor,
                    action="accepted_risk.expire",
                    target_type="impact",
                    target_id=impact_id,
                    reason="accepted risk expired",
                    before=before,
                    after=row_to_dict(updated),
                    occurred_at=checked_at,
                )
                expired.append({"impact_id": impact_id, "accepted_risk_id": row["accepted_risk_id"], "expires_at": row["expires_at"]})
        return {
            "checked_at": checked_at,
            "matched": len(rows),
            "expired": len(expired),
            "dry_run": False,
            "impacts": expired,
        }

    def enqueue_sla_expired_alerts(self, *, now: str | None = None, limit: int = 100, dry_run: bool = False, actor: str = "system") -> dict:
        checked_at = now or utcnow()
        checked_dt = parse_iso_datetime(checked_at)
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT i.id, i.alert_suppression_key, i.risk_level, i.status,
                       i.first_detected_at, i.package_name, i.resolved_version,
                       s.service_id, s.environment, a.advisory_id, a.summary
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                JOIN advisories a ON a.id = i.advisory_pk
                WHERE i.status IN ({",".join("?" for _ in ACTIVE_IMPACT_STATUSES)})
                ORDER BY i.first_detected_at ASC
                LIMIT ?
                """,
                (*ACTIVE_IMPACT_STATUSES, limit),
            ).fetchall()
            candidates = []
            for row in rows:
                impact = row_to_dict(row)
                sla = impact_sla(impact, checked_dt)
                if not sla["overdue"]:
                    continue
                suppression_key = f"{impact['alert_suppression_key']}:sla_expired"
                existing = conn.execute(
                    """
                    SELECT id, status
                    FROM alert_events
                    WHERE impact_pk = ? AND reason = 'sla_expired' AND alert_suppression_key = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (impact["id"], suppression_key),
                ).fetchone()
                candidate = {
                    "impact_id": impact["id"],
                    "service_id": impact["service_id"],
                    "environment": impact["environment"],
                    "advisory_id": impact["advisory_id"],
                    "package_name": impact["package_name"],
                    "risk_level": impact["risk_level"],
                    "sla": sla,
                    "alert_suppression_key": suppression_key,
                    "existing_alert_event_id": existing["id"] if existing else None,
                    "existing_alert_event_status": existing["status"] if existing else None,
                }
                candidates.append(candidate)
                if dry_run or existing:
                    continue
                payload = {
                    "impact_id": impact["id"],
                    "service_id": impact["service_id"],
                    "environment": impact["environment"],
                    "advisory_id": impact["advisory_id"],
                    "summary": impact["summary"],
                    "risk_level": impact["risk_level"],
                    "package_name": impact["package_name"],
                    "resolved_version": impact["resolved_version"],
                    "sla": sla,
                    "reason": "sla_expired",
                }
                conn.execute(
                    """
                    INSERT INTO alert_events (id, impact_pk, alert_suppression_key, reason, status, payload, created_at)
                    VALUES (?, ?, ?, 'sla_expired', 'pending', ?, ?)
                    """,
                    (str(uuid.uuid4()), impact["id"], suppression_key, json.dumps(payload, ensure_ascii=False), checked_at),
                )
                self.write_audit_log(
                    conn,
                    actor=actor,
                    action="sla.escalation.enqueue",
                    target_type="impact",
                    target_id=impact["id"],
                    reason="SLA expired alert enqueued",
                    before=None,
                    after={"alert_suppression_key": suppression_key, "sla": sla},
                    occurred_at=checked_at,
                )
        enqueued = [item for item in candidates if not item["existing_alert_event_id"]]
        return {
            "checked_at": checked_at,
            "matched": len(rows),
            "candidates": len(candidates),
            "enqueued": 0 if dry_run else len(enqueued),
            "dry_run": dry_run,
            "impacts": candidates,
        }

    def enqueue_daily_digest_alert(
        self,
        *,
        now: str | None = None,
        digest_date: str | None = None,
        timezone_name: str = "Asia/Seoul",
        limit: int = 100,
        dry_run: bool = False,
        actor: str = "system",
    ) -> dict:
        checked_at = now or utcnow()
        limit = bounded_int(limit, default=100, minimum=1, maximum=1000)
        digest_date = digest_date or local_date_for_timestamp(checked_at, timezone_name)
        suppression_key = f"daily_digest:{digest_date}:all"
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT i.id, i.alert_suppression_key, i.risk_level, i.status,
                       i.first_detected_at, i.last_seen_at, i.package_name,
                       i.resolved_version, i.fixed_version, i.freshness_status,
                       s.service_id, s.service_name, s.owner_team, s.environment,
                       a.advisory_id, a.summary, a.source, a.severity,
                       a.is_known_exploited, a.is_malicious_package
                FROM impacts i
                JOIN services s ON s.id = i.service_pk
                JOIN advisories a ON a.id = i.advisory_pk
                WHERE i.status IN ({",".join("?" for _ in ACTIVE_IMPACT_STATUSES)})
                  AND (
                    i.risk_level IN ('medium', 'low', 'info')
                    OR LOWER(s.environment) NOT IN ('prod', 'production')
                  )
                ORDER BY
                  CASE i.risk_level
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                  END ASC,
                  i.first_detected_at ASC
                LIMIT ?
                """,
                (*ACTIVE_IMPACT_STATUSES, limit),
            ).fetchall()
            existing = conn.execute(
                """
                SELECT id, status
                FROM alert_events
                WHERE reason = 'daily_digest' AND alert_suppression_key = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (suppression_key,),
            ).fetchone()
            items = [daily_digest_item(row) for row in rows]
            result = {
                "checked_at": checked_at,
                "digest_date": digest_date,
                "timezone": timezone_name,
                "matched": len(rows),
                "enqueued": 0,
                "dry_run": dry_run,
                "alert_suppression_key": suppression_key,
                "existing_alert_event_id": existing["id"] if existing else None,
                "existing_alert_event_status": existing["status"] if existing else None,
                "items": items,
            }
            if dry_run or existing or not items:
                return result
            payload = {
                "digest": {
                    "date": digest_date,
                    "timezone": timezone_name,
                    "scope": "all",
                    "matched": len(items),
                    "criteria": "active medium-or-lower impacts plus active non-production impacts",
                },
                "items": items,
                "reason": "daily_digest",
            }
            alert_event_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO alert_events (id, impact_pk, alert_suppression_key, reason, status, payload, created_at)
                VALUES (?, NULL, ?, 'daily_digest', 'pending', ?, ?)
                """,
                (alert_event_id, suppression_key, json.dumps(payload, ensure_ascii=False), checked_at),
            )
            self.write_audit_log(
                conn,
                actor=actor,
                action="daily_digest.enqueue",
                target_type="alert_digest",
                target_id=suppression_key,
                reason="daily digest alert enqueued",
                before=None,
                after={"alert_event_id": alert_event_id, "digest_date": digest_date, "matched": len(items)},
                occurred_at=checked_at,
            )
            result["enqueued"] = 1
            result["alert_event_id"] = alert_event_id
            return result

    def preview_daily_digest(self, body: dict) -> dict:
        return self.enqueue_daily_digest_alert(
            now=normalize_optional(body.get("now")),
            digest_date=normalize_optional(body.get("date")),
            timezone_name=normalize_optional(body.get("timezone")) or "Asia/Seoul",
            limit=bounded_int(body.get("limit"), default=100, minimum=1, maximum=1000),
            dry_run=True,
            actor=body.get("actor", "web-console"),
        )

    def alert_dispatcher_preflight(self, query: dict[str, list[str]]) -> dict:
        from .alert_preflight import run_alert_dispatcher_preflight

        limit = bounded_int(first_query_value(query, "limit"), default=50, minimum=1, maximum=1000)
        allow_missing = truthy(first_query_value(query, "allow_missing_default_channel"))
        return run_alert_dispatcher_preflight(self, limit=limit, require_default_channel=not allow_missing)

    def alert_dispatcher_activation_checklist(self, query: dict[str, list[str]]) -> dict:
        from .alert_preflight import run_alert_dispatcher_activation_check

        limit = bounded_int(first_query_value(query, "limit"), default=50, minimum=1, maximum=1000)
        return run_alert_dispatcher_activation_check(self, limit=limit)

    def requeue_alert_event(self, alert_event_id: str, body: dict) -> dict:
        actor = body.get("actor", "operator")
        reason = body.get("reason", "requeue dead-letter alert")
        now = utcnow()
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM alert_events WHERE id = ?", (alert_event_id,)).fetchone()
            if not row:
                raise ValueError("alert event not found")
            if row["status"] != "dead_letter":
                raise ValueError("only dead_letter alert events can be requeued")
            payload = json_column(row["payload"], {})
            payload["requeued_by"] = actor
            payload["requeue_reason"] = reason
            payload["requeued_at"] = now
            conn.execute(
                """
                UPDATE alert_events
                SET status = 'pending', retry_count = 0, next_attempt_at = NULL,
                    dispatch_lock_owner = NULL, dispatch_lock_expires_at = NULL,
                    payload = ?
                WHERE id = ?
                """,
                (json.dumps(payload, ensure_ascii=False), alert_event_id),
            )
            updated = conn.execute("SELECT id, status, retry_count, next_attempt_at, payload FROM alert_events WHERE id = ?", (alert_event_id,)).fetchone()
            self.write_audit_log(
                conn,
                actor=actor,
                action="alert_event.requeue",
                target_type="alert_event",
                target_id=alert_event_id,
                reason=reason,
                before={"id": row["id"], "status": row["status"], "retry_count": row["retry_count"], "next_attempt_at": row["next_attempt_at"]},
                after={key: updated[key] for key in updated.keys() if key != "payload"},
                occurred_at=now,
            )
        result = row_to_dict(updated)
        result["payload"] = json_column(result["payload"], {})
        return {"alert_event": result}

    def bulk_requeue_alert_events(self, body: dict) -> dict:
        status = body.get("status", "dead_letter")
        if status != "dead_letter":
            raise ValueError("bulk requeue only supports dead_letter alert events")
        limit = bounded_int(body.get("limit"), default=100, minimum=1, maximum=100)
        query = {"status": ["dead_letter"], "limit": [str(limit)], "offset": ["0"]}
        if search := str(body.get("q", "")).strip():
            query["q"] = [search]
        page = self.search_alert_events(query)
        requeued = []
        for event in page["alert_events"]:
            result = self.requeue_alert_event(
                event["id"],
                {
                    "actor": body.get("actor", "operator"),
                    "reason": body.get("reason", "bulk requeue dead-letter alerts"),
                },
            )
            requeued.append(result["alert_event"])
        return {
            "requeued": len(requeued),
            "matched": page["pagination"]["total"],
            "limit": limit,
            "alert_events": requeued,
        }

    def write_audit_log(
        self,
        conn,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        reason: str | None = None,
        before: dict | None = None,
        after: dict | None = None,
        occurred_at: str | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_logs (
                id, actor, action, target_type, target_id, reason,
                before_state, after_state, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                actor or "system",
                action,
                target_type,
                target_id,
                reason,
                json.dumps(before, ensure_ascii=False) if before is not None else None,
                json.dumps(after, ensure_ascii=False) if after is not None else None,
                occurred_at or utcnow(),
            ),
        )

    def search_audit_logs(self, query: dict[str, list[str]]) -> dict:
        where = []
        params = []
        for key in ("actor", "action", "target_type", "target_id"):
            if value := query.get(key, [None])[0]:
                where.append(f"{key} = ?")
                params.append(value)
        if search := query.get("q", [None])[0]:
            like = f"%{search.lower()}%"
            where.append(
                """
                (
                    lower(actor) LIKE ?
                    OR lower(action) LIKE ?
                    OR lower(target_type) LIKE ?
                    OR lower(target_id) LIKE ?
                    OR lower(COALESCE(reason, '')) LIKE ?
                )
                """
            )
            params.extend([like] * 5)
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        limit = bounded_int(query.get("limit", [None])[0], default=50, minimum=1, maximum=200)
        offset = bounded_int(query.get("offset", [None])[0], default=0, minimum=0, maximum=1_000_000)
        with self.db.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) AS c FROM audit_logs {sql_where}", tuple(params)).fetchone()["c"]
            rows = conn.execute(
                f"""
                SELECT id, actor, action, target_type, target_id, reason,
                       before_state, after_state, occurred_at
                FROM audit_logs
                {sql_where}
                ORDER BY occurred_at DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params + [limit, offset]),
            ).fetchall()
        logs = [sanitize_audit_log(row_to_dict(row)) for row in rows]
        return {
            "audit_logs": logs,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "returned": len(logs),
                "next_offset": offset + limit if offset + limit < total else None,
                "prev_offset": max(offset - limit, 0) if offset > 0 else None,
            },
        }

    def metrics(self) -> str:
        overview = self.overview()
        database_readiness = self.database_readiness_summary()
        migration = database_readiness.get("migration", {})
        cutover = database_readiness.get("cutover", {})
        required_cutover = database_readiness.get("cutover_required", {})
        postgres_preflight = database_readiness.get("postgres_preflight", {})
        required_blockers = sum(1 for check in required_cutover.get("checks", []) if check.get("status") == "blocker")
        lines = [
            f"sca_monitor_services {overview['service_count']}",
            f"sca_monitor_open_impacts {overview['open_impacts']}",
            f"sca_monitor_critical_impacts {overview['critical_impacts']}",
            f"sca_monitor_high_impacts {overview['high_impacts']}",
            f"sca_monitor_endpoint_unhealthy {overview['endpoint_unhealthy']}",
            f"sca_monitor_sla_overdue_impacts {overview['sla_overdue_impacts']}",
            f"sca_monitor_alert_readiness_ready {1 if overview['alert_readiness']['status'] == 'ready' else 0}",
            f"sca_monitor_advisory_sync_ready {1 if overview['advisory_sync_readiness']['status'] == 'ready' else 0}",
            f"sca_monitor_database_ready {1 if database_readiness['status'] == 'ready' else 0}",
            f"sca_monitor_database_backend_info{{backend=\"{metric_label(database_readiness['database_backend'])}\"}} 1",
            f"sca_monitor_migration_current_version {int(migration.get('current') or 0)}",
            f"sca_monitor_migration_required_version {int(migration.get('required') or 0)}",
            f"sca_monitor_migration_compatible {1 if migration.get('compatible') else 0}",
            f"sca_monitor_postgres_configured {1 if cutover.get('postgres_configured') else 0}",
            f"sca_monitor_postgres_cutover_status{{mode=\"{metric_label(cutover.get('mode', 'unknown'))}\",status=\"{metric_label(cutover.get('status', 'unknown'))}\"}} 1",
            f"sca_monitor_postgres_cutover_required_ready {1 if required_cutover.get('status') == 'ready' else 0}",
            f"sca_monitor_postgres_cutover_blockers {required_blockers}",
            f"sca_monitor_postgres_split_required {1 if required_cutover.get('require_split') else 0}",
            f"sca_monitor_postgres_split_ready {1 if postgres_preflight.get('split_ready') else 0}",
        ]
        lines.extend(self.operational_metric_lines())
        lines.append("")
        return "\n".join(lines)

    def operational_metric_lines(self) -> list[str]:
        now = datetime.now(timezone.utc)
        lines = []
        with self.db.connect() as conn:
            advisory_rows = conn.execute(
                """
                SELECT source, status, last_success_at, last_error_at, lease_acquire_failures
                FROM advisory_sync_state
                ORDER BY source
                """
            ).fetchall()
            poll_rows = conn.execute(
                """
                SELECT worker_name, checked_count, succeeded_count, failed_count, lease_acquire_failures
                FROM endpoint_poll_state
                ORDER BY worker_name
                """
            ).fetchall()
            alert_counts = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM alert_events
                GROUP BY status
                """
            ).fetchall()
            latest_new_alert = conn.execute(
                """
                SELECT ae.created_at AS alert_created_at, a.first_seen_at AS advisory_first_seen_at
                FROM alert_events ae
                JOIN impacts i ON i.id = ae.impact_pk
                JOIN advisories a ON a.id = i.advisory_pk
                WHERE ae.reason = 'new' AND a.first_seen_at IS NOT NULL
                ORDER BY ae.created_at DESC
                LIMIT 1
                """
            ).fetchone()
            stale_services = conn.execute(
                "SELECT COUNT(*) AS count FROM endpoint_health WHERE freshness_status = 'stale'"
            ).fetchone()["count"]

        advisory_sources = {row["source"]: row for row in advisory_rows}
        for source in INITIAL_ADVISORY_SYNC_SOURCES:
            row = advisory_sources.get(source)
            initialized = 1 if row and row["status"] == "ok" and row["last_success_at"] else 0
            lines.append(f'sca_monitor_advisory_sync_initialized{{source="{metric_label(source)}"}} {initialized}')
        for row in advisory_rows:
            lag = seconds_since(row["last_success_at"], now)
            if lag is not None:
                lines.append(f'sca_monitor_advisory_sync_lag_seconds{{source="{metric_label(row["source"])}"}} {lag}')
            failed = 1 if row["status"] == "error" else 0
            lines.append(f'sca_monitor_advisory_sync_failed{{source="{metric_label(row["source"])}"}} {failed}')
            error_age = seconds_since(row["last_error_at"], now)
            if error_age is not None:
                lines.append(f'sca_monitor_advisory_sync_last_error_age_seconds{{source="{metric_label(row["source"])}"}} {error_age}')
        for row in advisory_rows:
            failures = int(row["lease_acquire_failures"] or 0)
            if failures:
                lines.append(
                    f'sca_monitor_worker_lease_acquire_failures{{worker_type="advisory_sync",source="{metric_label(row["source"])}"}} {failures}'
                )
        if latest_new_alert:
            latency = seconds_between(latest_new_alert["advisory_first_seen_at"], latest_new_alert["alert_created_at"])
            if latency is not None:
                lines.append(f"new_advisory_to_alert_latency_seconds {latency}")

        total_checked = 0
        total_succeeded = 0
        for row in poll_rows:
            checked = int(row["checked_count"] or 0)
            succeeded = int(row["succeeded_count"] or 0)
            failed = int(row["failed_count"] or 0)
            total_checked += checked
            total_succeeded += succeeded
            worker_rate = succeeded / checked if checked else 0.0
            lines.append(f'sca_monitor_endpoint_poll_success_rate{{worker="{metric_label(row["worker_name"])}"}} {worker_rate:.6f}')
            lines.append(f'sca_monitor_endpoint_poll_checked_total{{worker="{metric_label(row["worker_name"])}"}} {checked}')
            lines.append(f'sca_monitor_endpoint_poll_failed_total{{worker="{metric_label(row["worker_name"])}"}} {failed}')
            lease_failures = int(row["lease_acquire_failures"] or 0)
            if lease_failures:
                lines.append(
                    f'sca_monitor_worker_lease_acquire_failures{{worker_type="endpoint_poll",worker="{metric_label(row["worker_name"])}"}} {lease_failures}'
                )
        total_rate = total_succeeded / total_checked if total_checked else 0.0
        lines.append(f"sca_monitor_endpoint_poll_success_rate {total_rate:.6f}")

        counts = {row["status"]: int(row["count"]) for row in alert_counts}
        pending = counts.get("pending", 0)
        sent = counts.get("sent", 0)
        failed = counts.get("failed", 0)
        dead_letter = counts.get("dead_letter", 0)
        delivered_total = sent + failed
        delivery_rate = sent / delivered_total if delivered_total else 0.0
        lines.append(f"sca_monitor_alert_delivery_success_rate {delivery_rate:.6f}")
        lines.append(f"sca_monitor_alert_outbox_pending_count {pending}")
        lines.append(f"sca_monitor_alert_dead_letter_count {dead_letter}")
        lines.append(f"sca_monitor_stale_services {stale_services}")
        return lines


def required(data: dict, key: str) -> str:
    value = data.get(key)
    if value is None or value == "":
        raise ValueError(f"{key} required")
    return str(value)


def sanitize_service(service: dict | None) -> dict | None:
    if service is None:
        return None
    sanitized = dict(service)
    auth_type = sanitized.get("status_auth_type") or "none"
    has_secret = bool(sanitized.get("auth_secret_ref") or sanitized.get("encrypted_auth_config"))
    sanitized["status_auth_type"] = auth_type
    sanitized["status_auth_configured"] = has_secret
    sanitized.pop("encrypted_auth_config", None)
    return sanitized


def sanitize_alert_channel(channel: dict | None) -> dict | None:
    from .alert_preflight import is_placeholder_url

    if channel is None:
        return None
    sanitized = dict(channel)
    target_url = sanitized.pop("target_url", None)
    sanitized["target_configured"] = bool(target_url)
    sanitized["target_url_masked"] = mask_url(target_url)
    sanitized["placeholder_target"] = is_placeholder_url(target_url)
    sanitized["enabled"] = bool(sanitized.get("enabled"))
    sanitized["is_default"] = bool(sanitized.get("is_default"))
    return sanitized


def sanitize_audit_log(row: dict | None) -> dict | None:
    if row is None:
        return None
    sanitized = dict(row)
    sanitized["before"] = parse_json_field(sanitized.pop("before_state", None))
    sanitized["after"] = parse_json_field(sanitized.pop("after_state", None))
    return sanitized


def sanitize_dependency(row: dict | None) -> dict | None:
    if row is None:
        return None
    sanitized = dict(row)
    sanitized["direct_dependency"] = bool(sanitized.get("direct_dependency"))
    return sanitized


def sanitize_service_impact(row: dict | None) -> dict | None:
    if row is None:
        return None
    sanitized = dict(row)
    sanitized["is_known_exploited"] = bool(sanitized.get("is_known_exploited"))
    sanitized["is_malicious_package"] = bool(sanitized.get("is_malicious_package"))
    return enrich_impact_sla(sanitized)


def enrich_impact_sla(impact: dict) -> dict:
    enriched = dict(impact)
    enriched["sla"] = impact_sla(enriched, datetime.now(timezone.utc))
    return enriched


def impact_sla(impact, now: datetime) -> dict:
    risk_level = str(impact.get("risk_level") or "info").lower()
    policy_hours = DEFAULT_SLA_HOURS.get(risk_level, DEFAULT_SLA_HOURS["info"])
    first_detected_at = impact.get("first_detected_at")
    status = impact.get("status")
    deadline_at = None
    seconds_until_deadline = None
    overdue = False
    if first_detected_at:
        try:
            detected = parse_iso_datetime(first_detected_at)
            deadline = detected + timedelta(hours=policy_hours)
            deadline_at = deadline.isoformat()
            seconds_until_deadline = int((deadline - now).total_seconds())
            overdue = status in ACTIVE_IMPACT_STATUSES and seconds_until_deadline < 0
        except (TypeError, ValueError):
            deadline_at = None
            seconds_until_deadline = None
            overdue = False
    return {
        "policy_hours": policy_hours,
        "deadline_at": deadline_at,
        "overdue": overdue,
        "seconds_until_deadline": seconds_until_deadline,
    }


def parse_json_field(value):
    if value is None:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def mask_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(value)
    if not parsed.netloc:
        return "***"
    return f"{parsed.scheme}://{parsed.netloc}/..."


def endpoint_auth_config_from_body(body: dict) -> tuple[str | None, str | None, str | None]:
    auth_type = normalize_optional(body.get("status_auth_type") or body.get("endpoint_auth_type"))
    secret_ref = normalize_optional(body.get("auth_secret_ref"))
    bearer_token = normalize_optional(body.get("status_bearer_token") or body.get("endpoint_bearer_token"))
    auth_header = normalize_optional(body.get("auth_header"))
    if bearer_token:
        return "bearer_token", secret_ref, json.dumps({"bearer_token": bearer_token})
    if auth_header and auth_header.lower().startswith("bearer "):
        return "bearer_token", secret_ref, json.dumps({"bearer_token": auth_header.split(" ", 1)[1]})
    if auth_type and auth_type != "none":
        return auth_type, secret_ref, None
    return None, secret_ref, None


def endpoint_auth_header(service, body: dict) -> str | None:
    override = normalize_optional(body.get("auth_header"))
    if override:
        return override
    direct_token = normalize_optional(body.get("status_bearer_token") or body.get("endpoint_bearer_token"))
    if direct_token:
        return f"Bearer {direct_token}"
    auth_type = service["status_auth_type"] or "none"
    if auth_type == "bearer_token":
        config = service["encrypted_auth_config"]
        if not config:
            raise PermissionError("endpoint bearer token is not configured")
        if isinstance(config, bytes):
            config = config.decode("utf-8")
        token = json.loads(config).get("bearer_token")
        if not token:
            raise PermissionError("endpoint bearer token is not configured")
        return f"Bearer {token}"
    if auth_type in ("none", ""):
        return None
    raise PermissionError(f"endpoint auth type is not implemented: {auth_type}")


def normalize_optional(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() not in ("", "0", "false", "no", "off")


def seconds_since(value: str | None, now: datetime) -> int | None:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, int((now - parsed).total_seconds()))


def seconds_between(start_value: str | None, end_value: str | None) -> int | None:
    if not start_value or not end_value:
        return None
    try:
        start = parse_iso_datetime(start_value)
        end = parse_iso_datetime(end_value)
    except (TypeError, ValueError):
        return None
    return max(0, int((end - start).total_seconds()))


def timestamp_is_due(value: str | None, now_value: str) -> bool:
    if not value:
        return False
    try:
        target = parse_iso_datetime(value)
        now = parse_iso_datetime(now_value)
    except ValueError:
        return str(value) <= str(now_value)
    return target <= now


def parse_iso_datetime(value: str) -> datetime:
    text = str(value)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def metric_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def canonical_source_priority(source: str) -> int:
    priorities = {
        "OSV": 0,
        "OpenSSF": 1,
        "GHSA": 2,
        "NVD": 3,
        "CISA_KEV": 4,
    }
    return priorities.get(str(source), 100)


def merged_advisory_values(target: dict, source: dict) -> dict:
    target_severity = str(target.get("severity") or "medium").lower()
    source_severity = str(source.get("severity") or "medium").lower()
    severity = (
        source_severity
        if RISK_RANK.get(source_severity, RISK_RANK["info"]) < RISK_RANK.get(target_severity, RISK_RANK["info"])
        else target_severity
    )
    target_raw = json_column(target.get("raw_payload"), {})
    source_raw = json_column(source.get("raw_payload"), {})
    if not isinstance(target_raw, dict):
        target_raw = {"value": target_raw}
    merged_sources = list(target_raw.get("_merged_sources") or [])
    merged_sources.append(
        {
            "advisory_id": source.get("advisory_id"),
            "source": source.get("source"),
            "raw_payload": source_raw,
        }
    )
    raw_payload = {**target_raw, "_merged_sources": merged_sources}
    return {
        "severity": severity,
        "affected_versions": merge_json_lists(json_column(target.get("affected_versions"), []), json_column(source.get("affected_versions"), [])),
        "affected_ranges": merge_json_lists(json_column(target.get("affected_ranges"), []), json_column(source.get("affected_ranges"), [])),
        "fixed_version": target.get("fixed_version") or source.get("fixed_version"),
        "is_known_exploited": bool(target.get("is_known_exploited")) or bool(source.get("is_known_exploited")),
        "is_malicious_package": bool(target.get("is_malicious_package")) or bool(source.get("is_malicious_package")),
        "published_at": min_optional_text(target.get("published_at"), source.get("published_at")),
        "modified_at": max_optional_text(target.get("modified_at"), source.get("modified_at")),
        "raw_payload": raw_payload,
    }


def merge_json_lists(left: list, right: list) -> list:
    seen = set()
    merged = []
    for item in list(left or []) + list(right or []):
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def min_optional_text(left, right):
    values = [str(value) for value in (left, right) if value]
    return min(values) if values else None


def max_optional_text(left, right):
    values = [str(value) for value in (left, right) if value]
    return max(values) if values else None


def highest_risk(left, right) -> str:
    left_value = str(left or "medium").lower()
    right_value = str(right or "medium").lower()
    return (
        right_value
        if RISK_RANK.get(right_value, RISK_RANK["info"]) < RISK_RANK.get(left_value, RISK_RANK["info"])
        else left_value
    )


def nvd_cwes(raw_payload: dict) -> list[str]:
    cwes: list[str] = []
    seen: set[str] = set()
    if not isinstance(raw_payload, dict):
        return cwes
    for weakness in raw_payload.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").strip().upper()
            if value.startswith("CWE-") and value not in seen:
                seen.add(value)
                cwes.append(value)
    return cwes


def nvd_references(raw_payload: dict) -> list[dict[str, object]]:
    references: list[dict[str, object]] = []
    seen: set[str] = set()
    if not isinstance(raw_payload, dict):
        return references
    for item in raw_payload.get("references") or []:
        url = str(item.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        reference: dict[str, object] = {"url": url}
        if item.get("source"):
            reference["source"] = str(item["source"])
        tags = [str(tag) for tag in item.get("tags") or [] if str(tag)]
        if tags:
            reference["tags"] = tags
        references.append(reference)
    return references


def advisory_import_from_row(row: dict) -> AdvisoryImport:
    return AdvisoryImport(
        advisory_id=row["advisory_id"],
        source=row["source"],
        summary=row["summary"],
        severity=row["severity"],
        ecosystem=row["ecosystem"],
        package_name=row["package_name"],
        canonical_package_name=row["canonical_package_name"],
        affected_versions=json_column(row["affected_versions"], []),
        affected_ranges=json_column(row["affected_ranges"], []),
        fixed_version=row.get("fixed_version"),
        is_known_exploited=bool(row["is_known_exploited"]),
        is_malicious_package=bool(row["is_malicious_package"]),
        published_at=row.get("published_at"),
        modified_at=row.get("modified_at"),
        raw_payload=json_column(row["raw_payload"], {}),
    )


def safe_json_loads(value, default):
    return json_column(value, default)


def advisory_alias_values(row: dict | None) -> set[str]:
    if not row:
        return set()
    values = {alias["alias_value"] for alias in advisory_aliases_for_row(row)}
    values.add(normalize_cve_id(row.get("advisory_id")))
    return {value for value in values if value}


def advisory_aliases_for_import(advisory: AdvisoryImport) -> list[dict[str, str]]:
    return advisory_aliases_for_row(
        {
            "advisory_id": advisory.advisory_id,
            "source": advisory.source,
            "raw_payload": advisory.raw_payload,
            "is_malicious_package": advisory.is_malicious_package,
        }
    )


def advisory_aliases_for_row(row: dict | None) -> list[dict[str, str]]:
    if not row:
        return []
    values: dict[str, set[str]] = {"CVE": set(), "GHSA": set(), "OSV": set(), "MAL": set()}
    add_alias_value(values, row.get("advisory_id"))
    try:
        raw_payload = json_column(row.get("raw_payload"), {})
    except (TypeError, ValueError):
        raw_payload = {}
    extract_alias_values(raw_payload, values)
    aliases = []
    for alias_type in ("CVE", "GHSA", "OSV", "MAL"):
        for alias_value in sorted(values[alias_type]):
            aliases.append({"alias_type": alias_type, "alias_value": alias_value})
    return aliases


def add_alias_value(values: dict[str, set[str]], value) -> None:
    for alias_type, alias_value in normalize_advisory_aliases(value):
        values.setdefault(alias_type, set()).add(alias_value)


def normalize_advisory_aliases(value) -> list[tuple[str, str]]:
    if value is None:
        return []
    text = str(value).strip().upper()
    if text.startswith("CISA_KEV:"):
        text = text.split(":", 1)[1]
    aliases: list[tuple[str, str]] = []
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", text):
        aliases.append(("CVE", text))
    if re.fullmatch(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", text):
        aliases.append(("GHSA", text))
    if text.startswith("OSV-") or text.startswith("PYSEC-"):
        aliases.append(("OSV", text))
    if text.startswith("MAL-"):
        aliases.append(("MAL", text))
    return aliases


def extract_alias_values(value, values: dict[str, set[str]]) -> None:
    if isinstance(value, dict):
        if value.get("type") and value.get("value"):
            add_alias_value(values, value.get("value"))
        for key in ("id", "ghsa_id", "cve_id", "cveID"):
            add_alias_value(values, value.get(key))
        for item in value.values():
            extract_alias_values(item, values)
        return
    if isinstance(value, list):
        for item in value:
            extract_alias_values(item, values)
        return
    add_alias_value(values, value)


def extract_cve_values(value) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for item in value.values():
            found.update(extract_cve_values(item))
        return found
    if isinstance(value, list):
        for item in value:
            found.update(extract_cve_values(item))
        return found
    cve = normalize_cve_id(value)
    return {cve} if cve else found


def normalize_cve_id(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if text.startswith("CISA_KEV:"):
        text = text.split(":", 1)[1]
    return text if text.startswith("CVE-") else None


def bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(number, maximum))


def first_query_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key) or []
    return values[0] if values else None


def truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def local_date_for_timestamp(timestamp: str, timezone_name: str) -> str:
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {timezone_name}") from exc
    return parse_iso_datetime(timestamp).astimezone(zone).date().isoformat()


def daily_digest_item(row) -> dict:
    return {
        "impact_id": row["id"],
        "service_id": row["service_id"],
        "service_name": row["service_name"],
        "owner_team": row["owner_team"],
        "environment": row["environment"],
        "advisory_id": row["advisory_id"],
        "source": row["source"],
        "summary": row["summary"],
        "severity": row["severity"],
        "risk_level": row["risk_level"],
        "status": row["status"],
        "package_name": row["package_name"],
        "resolved_version": row["resolved_version"],
        "fixed_version": row["fixed_version"],
        "freshness_status": row["freshness_status"],
        "first_detected_at": row["first_detected_at"],
        "last_seen_at": row["last_seen_at"],
        "known_exploited": bool(row["is_known_exploited"]),
        "malicious_package": bool(row["is_malicious_package"]),
    }


def parse_csv_header(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def fetch_json_endpoint(endpoint_url: str, auth_header: str | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    request = Request(endpoint_url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310 - user-configured service endpoint test.
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                raise ValueError("endpoint did not return JSON")
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
            raise PermissionError(f"endpoint returned HTTP {exc.code}") from exc
        raise ConnectionError(f"endpoint returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise ConnectionError(str(exc.reason)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError("endpoint returned invalid JSON") from exc


def utcnow_after_seconds(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def remaining_ttl_days(expires_at: str | None) -> int:
    if not expires_at:
        return 90
    try:
        expires = parse_iso_datetime(expires_at)
    except (TypeError, ValueError):
        return 90
    remaining = expires - datetime.now(timezone.utc)
    if remaining.total_seconds() <= 0:
        return 1
    return max(1, min(3650, int((remaining.total_seconds() + 86399) // 86400)))


def run() -> None:
    settings = load_settings()
    app = ScaMonitorApp(settings)
    server = ThreadingHTTPServer((settings.host, settings.port), app.handler())
    print(f"SCA Monitor listening on http://{settings.host}:{settings.port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
