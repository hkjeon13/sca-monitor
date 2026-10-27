"""Account-scoped console APIs. Existing collectors/matching remain shared infrastructure."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ipaddress
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from urllib.parse import unquote, urlparse

from .db import json_column, utcnow

SOURCES = ("OSV", "GHSA", "OpenSSF", "CISA_KEV", "NVD")
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ACTIVE = ("open", "acknowledged", "in_progress")
COOKIE = "sca_session"


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ApiError(400, "비밀번호는 12~256자로 입력해 주세요.")
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return "pbkdf2_sha256$600000$" + salt.hex() + "$" + key.hex()


def password_matches(password, encoded):
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(rounds) != 600000:
            return False
        key = hashlib.pbkdf2_hmac(
            "sha256", str(password).encode(), bytes.fromhex(salt), int(rounds)
        )
        return hmac.compare_digest(key.hex(), expected)
    except (ValueError, TypeError):
        return False


def email_value(value):
    email = str(value or "").strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ApiError(400, "올바른 이메일 주소를 입력해 주세요.")
    return email


def integer(value, default=25, maximum=100):
    try:
        return max(1, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


def cursor_value(value):
    if not value:
        return 0
    try:
        offset = int(base64.urlsafe_b64decode(value.encode()).decode())
        if not 0 <= offset <= 10_000_000:
            raise ValueError()
        return offset
    except Exception as exc:
        raise ApiError(400, "잘못된 페이지 커서입니다.") from exc


def page(items, total, offset, size):
    return {
        "items": items,
        "total": total,
        "page_size": size,
        "offset": offset,
        "next_cursor": base64.urlsafe_b64encode(str(offset + size).encode()).decode()
        if offset + size < total
        else None,
        "as_of": utcnow(),
    }


def text(body, key, maximum=200, required=True):
    value = str(body.get(key) or "").strip()
    if (required and not value) or len(value) > maximum:
        raise ApiError(
            400,
            f"{key}: 1~{maximum}자로 입력해 주세요."
            if required
            else f"{key}: 최대 {maximum}자입니다.",
        )
    return value


def inventory_freshness(last_seen, environment, threshold=None):
    if not last_seen:
        return "unknown"
    try:
        seen = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        maximum = threshold or {"prod": 3600, "stage": 86400, "dev": 604800}.get(
            environment, 3600
        )
        return (
            "fresh"
            if (datetime.now(timezone.utc) - seen).total_seconds() <= maximum
            else "stale"
        )
    except (ValueError, TypeError):
        return "unknown"


class WorkspaceAPI:
    def __init__(self, app):
        self.app, self.db = app, app.db
        self._source_cache = None
        self._source_cache_at = None

    def client_address(self, request):
        peer = ipaddress.ip_address(request.client_address[0])
        if peer.is_loopback and self.app.settings.app_env == "prod":
            forwarded = request.headers.get("CF-Connecting-IP")
            if forwarded:
                try:
                    return str(ipaddress.ip_address(forwarded))
                except ValueError:
                    pass
        return str(peer)

    def reply(self, request, body, status=200, cookie=None):
        if (
            status < 300
            and request.command in ("POST", "PATCH")
            and request.path.startswith("/api/v2/")
            and "/auth/" not in request.path
        ):
            actor = self.session_user(request)
            with self.db.connect() as conn:
                self.app.write_audit_log(
                    conn,
                    actor=actor["email"],
                    action="workspace." + request.command.lower(),
                    target_type="workspace",
                    target_id=request.path.split("?")[0],
                    reason="authenticated workspace change",
                    before=None,
                    after={"status": status},
                    occurred_at=utcnow(),
                )
        payload = json.dumps(body, ensure_ascii=False, default=str).encode()
        request.send_response(status)
        request.send_header("Content-Type", "application/json; charset=utf-8")
        request.send_header("Cache-Control", "no-store")
        request.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            request.send_header("Set-Cookie", cookie)
        request.send_header("Content-Length", str(len(payload)))
        request.end_headers()
        request.wfile.write(payload)

    def session_user(self, request, required=True):
        cookies = SimpleCookie()
        try:
            cookies.load(request.headers.get("Cookie", ""))
        except CookieError:
            cookies.clear()
        token = cookies[COOKIE].value if COOKIE in cookies else ""
        with self.db.connect() as conn:
            row = (
                conn.execute(
                    """SELECT u.id,u.email,u.display_name,u.is_admin,s.csrf_token
                FROM workspace_sessions s JOIN workspace_users u ON u.id=s.user_id
                WHERE s.token_hash=? AND s.expires_at>? AND u.disabled=0""",
                    (digest(token), utcnow()),
                ).fetchone()
                if token
                else None
            )
        if not row:
            if required:
                raise ApiError(401, "로그인이 필요합니다.")
            return None
        user = dict(row)
        user["is_admin"] = bool(user["is_admin"])
        return user

    def csrf(self, request, user):
        if not hmac.compare_digest(
            request.headers.get("X-CSRF-Token", ""), user["csrf_token"]
        ):
            raise ApiError(403, "페이지를 새로고침한 뒤 다시 시도해 주세요.")
        self.check_origin(request)

    def check_origin(self, request):
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc != request.headers.get("Host"):
            raise ApiError(403, "허용되지 않은 요청 출처입니다.")

    def new_session(self, user_id):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        now = datetime.now(timezone.utc)
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO workspace_sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",
                (
                    digest(token),
                    user_id,
                    csrf,
                    (now + timedelta(hours=12)).isoformat(),
                    now.isoformat(),
                ),
            )
        secure = self.app.settings.app_env not in ("dev", "test")
        cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200" + (
            "; Secure" if secure else ""
        )
        return cookie

    def make_setup_token(self, email=None, admin=False):
        token = secrets.token_urlsafe(32)
        with self.db.connect() as conn:
            if (
                admin
                and conn.execute(
                    "SELECT COUNT(*) AS c FROM workspace_users"
                ).fetchone()["c"]
            ):
                raise ApiError(409, "관리자 계정이 이미 있습니다.")
            conn.execute(
                "INSERT INTO workspace_setup_tokens(token_hash,email,is_admin,expires_at) VALUES(?,?,?,?)",
                (
                    digest(token),
                    email_value(email) if email else None,
                    int(admin),
                    (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                ),
            )
        return token

    def setup(self, body):
        email = email_value(body.get("email"))
        hashed = password_hash(body.get("password"))
        name = text(body, "display_name", 100)
        now = utcnow()
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM workspace_setup_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?",
                (digest(str(body.get("token", ""))), now),
            ).fetchone()
            if not row or (row["email"] and row["email"] != email):
                raise ApiError(400, "설정 링크가 만료되었거나 유효하지 않습니다.")
            existing = conn.execute(
                "SELECT id FROM workspace_users WHERE email=?", (email,)
            ).fetchone()
            if existing and (not row["email"] or row["is_admin"]):
                raise ApiError(409, "이미 등록된 이메일입니다. 로그인해 주세요.")
            changed = conn.execute(
                "UPDATE workspace_setup_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                (now, row["token_hash"]),
            ).rowcount
            if changed != 1:
                raise ApiError(409, "이미 사용된 설정 링크입니다.")
            if (
                row["is_admin"]
                and conn.execute(
                    "SELECT COUNT(*) AS c FROM workspace_users"
                ).fetchone()["c"]
            ):
                raise ApiError(409, "관리자 초기 설정이 완료되었습니다.")
            uid = existing["id"] if existing else str(uuid.uuid4())
            if existing:
                conn.execute(
                    "UPDATE workspace_users SET password_hash=?,display_name=? WHERE id=?",
                    (hashed, name, uid),
                )
                conn.execute("DELETE FROM workspace_sessions WHERE user_id=?", (uid,))
            else:
                conn.execute(
                    "INSERT INTO workspace_users(id,email,display_name,password_hash,is_admin,created_at) VALUES(?,?,?,?,?,?)",
                    (uid, email, name, hashed, row["is_admin"], now),
                )
        return uid

    def login(self, request, body):
        email = str(body.get("email", "")).strip().lower()[:254]
        password = str(body.get("password", ""))[:257]
        key = digest(email + "|" + self.client_address(request))
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=15)).isoformat()
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM workspace_login_attempts WHERE attempt_key=?", (key,)
            ).fetchone()
            if row and str(row["window_start"]) > cutoff and row["attempts"] >= 10:
                raise ApiError(
                    429, "로그인 시도가 많습니다. 15분 후 다시 시도해 주세요."
                )
            conn.execute(
                """INSERT INTO workspace_login_attempts(attempt_key,attempts,window_start) VALUES(?,1,?)
                ON CONFLICT(attempt_key) DO UPDATE SET attempts=CASE WHEN workspace_login_attempts.window_start<? THEN 1 ELSE workspace_login_attempts.attempts+1 END,
                window_start=CASE WHEN workspace_login_attempts.window_start<? THEN excluded.window_start ELSE workspace_login_attempts.window_start END""",
                (key, now.isoformat(), cutoff, cutoff),
            )
            user = conn.execute(
                "SELECT * FROM workspace_users WHERE email=? AND disabled=0", (email,)
            ).fetchone()
        # Always perform the same expensive KDF, including for unknown accounts.
        fallback = "pbkdf2_sha256$600000$" + "00" * 16 + "$" + "00" * 32
        valid = password_matches(password, user["password_hash"] if user else fallback)
        if not user or not valid:
            raise ApiError(401, "이메일 또는 비밀번호가 올바르지 않습니다.")
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE workspace_login_attempts SET attempts=0 WHERE attempt_key=?",
                (key,),
            )
        return self.new_session(user["id"])

    def require_project(self, user, project_id, write=False, owner=False):
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT p.*,m.role FROM projects p LEFT JOIN project_memberships m
                ON m.project_id=p.id AND m.user_id=? WHERE p.id=?""",
                (user["id"], project_id),
            ).fetchone()
        if not row or (not row["role"] and not user["is_admin"]):
            raise ApiError(404, "프로젝트를 찾을 수 없습니다.")
        project = dict(row)
        role = "owner" if user["is_admin"] else project["role"]
        if (write and role == "viewer") or (owner and role != "owner"):
            raise ApiError(403, "이 작업을 수행할 프로젝트 권한이 없습니다.")
        project["role"] = role
        return project

    def scope_sql(self, user, alias="pt", project_id=None):
        if project_id:
            self.require_project(user, project_id)
            return f"{alias}.project_id=?", [project_id]
        if user["is_admin"]:
            return "1=1", []
        return (
            f"{alias}.project_id IN (SELECT project_id FROM project_memberships WHERE user_id=?)",
            [user["id"]],
        )

    def projects(self, user):
        clause = "1=1" if user["is_admin"] else "m.user_id=?"
        params = [] if user["is_admin"] else [user["id"]]
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""SELECT DISTINCT p.*,
                (SELECT role FROM project_memberships WHERE project_id=p.id AND user_id=?) AS role,
                (SELECT COUNT(*) FROM project_targets WHERE project_id=p.id) AS target_count,
                (SELECT COUNT(*) FROM impacts i JOIN project_targets pt ON pt.service_pk=i.service_pk WHERE pt.project_id=p.id AND i.status IN ('open','acknowledged','in_progress')) AS open_findings
                FROM projects p LEFT JOIN project_memberships m ON m.project_id=p.id WHERE {clause}
                ORDER BY p.updated_at DESC""",
                [user["id"]] + params,
            ).fetchall()
        return [
            dict(r) | {"role": "owner" if user["is_admin"] else r["role"]} for r in rows
        ]

    def create_project(self, user, body):
        pid, now = str(uuid.uuid4()), utcnow()
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO projects(id,name,description,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (
                    pid,
                    text(body, "name", 100),
                    text(body, "description", 2000, False),
                    user["id"],
                    now,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO project_memberships(project_id,user_id,role) VALUES(?,?,?)",
                (pid, user["id"], "owner"),
            )
            conn.execute(
                "INSERT INTO project_alert_rules(project_id,updated_at) VALUES(?,?)",
                (pid, now),
            )
        return self.require_project(user, pid)

    def targets(self, user, project_id):
        self.require_project(user, project_id)
        with self.db.connect() as conn:
            rows = conn.execute(
                """SELECT pt.*,s.service_id,s.service_name,s.environment,s.collection_mode,
                s.status_endpoint_url,s.latest_snapshot_id,eh.collection_status,eh.freshness_status,
                s.freshness_threshold_seconds,
                (SELECT MAX(collected_at) FROM dependency_snapshots WHERE service_pk=s.id) AS last_collected_at,
                (SELECT last_confirmed_at FROM dependency_snapshots WHERE id=s.latest_snapshot_id) AS last_confirmed_at,
                (SELECT COUNT(*) FROM impacts WHERE service_pk=s.id AND status IN ('open','acknowledged','in_progress')) AS open_findings
                FROM project_targets pt JOIN services s ON s.id=pt.service_pk LEFT JOIN endpoint_health eh ON eh.service_pk=s.id
                WHERE pt.project_id=? ORDER BY pt.created_at DESC""",
                (project_id,),
            ).fetchall()
        return [
            dict(r)
            | {
                "metadata": json_column(r["metadata"], {}),
                "freshness_status": inventory_freshness(
                    r["last_confirmed_at"] or r["last_collected_at"],
                    r["environment"],
                    r["freshness_threshold_seconds"],
                ),
            }
            for r in rows
        ]

    def create_target(self, user, project_id, body):
        self.require_project(user, project_id, write=True)
        name = text(body, "name", 100)
        environment = str(body.get("environment") or "prod")
        if environment not in ("prod", "stage", "dev"):
            raise ApiError(400, "environment는 prod, stage, dev 중 하나여야 합니다.")
        mode = body.get("collection_mode", "push")
        if mode not in ("push", "poll"):
            raise ApiError(400, "collection_mode는 push 또는 poll이어야 합니다.")
        metadata = body.get("metadata") or {}
        if not isinstance(metadata, dict) or len(json.dumps(metadata)) > 10000:
            raise ApiError(400, "환경 메타데이터는 10KB 이하 객체여야 합니다.")
        target_id = str(uuid.uuid4())
        service = self.app.create_service(
            {
                **body,
                "service_id": "project-" + target_id,
                "service_name": name,
                "owner_team": "project:" + project_id,
                "environment": environment,
                "collection_mode": mode,
            }
        )["service"]
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO project_targets(id,project_id,service_pk,target_key,metadata,created_at) VALUES(?,?,?,?,?,?)",
                (
                    target_id,
                    project_id,
                    service["id"],
                    target_id,
                    json.dumps(metadata),
                    utcnow(),
                ),
            )
        return next(t for t in self.targets(user, project_id) if t["id"] == target_id)

    def target(self, user, project_id, target_id, write=False):
        self.require_project(user, project_id, write=write)
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT pt.*,s.service_id,s.environment,s.service_name,s.collection_mode,s.status_endpoint_url FROM project_targets pt JOIN services s ON s.id=pt.service_pk
                WHERE pt.project_id=? AND pt.id=?""",
                (project_id, target_id),
            ).fetchone()
        if not row:
            raise ApiError(404, "서비스/환경을 찾을 수 없습니다.")
        return dict(row)

    def inventory(self, user, project_id, query):
        self.require_project(user, project_id)
        where, params = ["pt.project_id=?", "ds.is_latest"], [project_id]
        if query.get("target_id"):
            where.append("pt.id=?")
            params.append(query["target_id"][0])
        if query.get("q"):
            where.append("lower(d.package_name) LIKE ?")
            params.append("%" + query["q"][0].lower() + "%")
        size, offset = (
            integer(query.get("page_size", [25])[0]),
            cursor_value(query.get("cursor", [None])[0]),
        )
        joins = """FROM dependencies d JOIN dependency_snapshots ds ON ds.id=d.snapshot_pk
            JOIN project_targets pt ON pt.service_pk=ds.service_pk JOIN services s ON s.id=pt.service_pk"""
        with self.db.connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c {joins} WHERE " + " AND ".join(where), params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT d.*,s.service_name,s.environment,s.freshness_threshold_seconds,pt.id AS target_id,ds.collected_at,ds.last_confirmed_at,ds.freshness_status {joins}
                WHERE {" AND ".join(where)} ORDER BY lower(d.package_name),d.id LIMIT ? OFFSET ?""",
                params + [size, offset],
            ).fetchall()
        return page(
            [
                dict(r)
                | {
                    "freshness_status": inventory_freshness(
                        r["last_confirmed_at"] or r["collected_at"],
                        r["environment"],
                        r["freshness_threshold_seconds"],
                    )
                }
                for r in rows
            ],
            total,
            offset,
            size,
        )

    def sources(self):
        now = datetime.now(timezone.utc)
        if (
            self._source_cache is not None
            and (now - self._source_cache_at).total_seconds() < 30
        ):
            return self._source_cache
        with self.db.connect() as conn:
            counts = {
                r["source"]: r["c"]
                for r in conn.execute(
                    "SELECT source,COUNT(*) AS c FROM advisories GROUP BY source"
                ).fetchall()
            }
            states = {
                r["source"]: dict(r)
                for r in conn.execute("SELECT * FROM advisory_sync_state").fetchall()
            }
        running = None
        try:
            progress = json.loads(
                (self.app.settings.data_dir / "source-sync-progress.json").read_text()
            )
            if progress.get("status") == "running":
                os.kill(int(progress["pid"]), 0)
                running = progress.get("source")
        except (OSError, ValueError, KeyError, TypeError):
            pass
        items = []
        for source in SOURCES:
            state = states.get(source, {})
            last = state.get("last_success_at")
            lag = None
            if last:
                try:
                    lag = max(
                        0,
                        int((now - datetime.fromisoformat(str(last))).total_seconds()),
                    )
                except ValueError:
                    pass
            status = (
                "failed"
                if state.get("status") in ("error", "failed")
                else "partial"
                if state.get("status") == "partial"
                else "not_initialized"
                if not last
                else "stale"
                if lag is None
                or lag > self.app.settings.advisory_sync_stale_after_seconds
                else "fresh"
            )
            if running == source:
                status = "running"
            items.append(
                {
                    "source": source,
                    "stored_count": counts.get(source, 0),
                    "status": status,
                    "last_success_at": last,
                    "last_run_at": state.get("last_run_at"),
                    "last_error_message": state.get("last_error_message"),
                    "lag_seconds": lag,
                    "cursor": state.get("cursor"),
                    "coverage": "로컬에 수집된 범위이며 전체 공개 데이터의 완전성을 보장하지 않습니다.",
                }
            )
            items[-1]["configured_scope"] = {
                "OSV": "생태계: " + os.getenv("SCA_MONITOR_OSV_ECOSYSTEMS", "npm"),
                "GHSA": "GitHub reviewed · 변경분 전체 페이지",
                "OpenSSF": "npm 생태계의 MAL 보고",
                "CISA_KEV": "KEV 전체 카탈로그",
                "NVD": "저장된 커서 이후 변경분 (과거 전체 적재와 별개)",
            }[source]
        self._source_cache, self._source_cache_at = items, now
        return items

    def advisory_search(self, user, query):
        where, params = [], []
        for key, column in (
            ("source", "a.source"),
            ("ecosystem", "a.ecosystem"),
            ("severity", "a.severity"),
        ):
            if query.get(key) and query[key][0]:
                value = query[key][0]
                if key == "source" and value not in SOURCES:
                    raise ApiError(400, "지원하지 않는 소스입니다.")
                where.append(column + "=?")
                params.append(value)
        if query.get("q") and query["q"][0]:
            like = "%" + query["q"][0].lower()[:200] + "%"
            where.append("""(lower(a.advisory_id) LIKE ? OR lower(a.summary) LIKE ? OR lower(a.package_name) LIKE ?
                OR EXISTS(SELECT 1 FROM advisory_aliases aa WHERE aa.advisory_pk=a.id AND lower(aa.alias_value) LIKE ?))""")
            params.extend([like] * 4)
        if query.get("package"):
            where.append("lower(a.package_name)=?")
            params.append(query["package"][0].lower())
        for key, column in (
            ("kev", "a.is_known_exploited"),
            ("malicious", "a.is_malicious_package"),
        ):
            if query.get(key) and query[key][0] in ("true", "false"):
                where.append(column + "=?")
                params.append(query[key][0] == "true")
        if query.get("modified_from") and query["modified_from"][0]:
            where.append("a.modified_at>=?")
            params.append(query["modified_from"][0])
        if query.get("project_id") and query["project_id"][0]:
            pid = query["project_id"][0]
            self.require_project(user, pid)
            where.append(
                "EXISTS(SELECT 1 FROM impacts i JOIN project_targets pt ON pt.service_pk=i.service_pk WHERE i.advisory_pk=a.id AND pt.project_id=?)"
            )
            params.append(pid)
        clause = " AND ".join(where) or "1=1"
        size, offset = (
            integer(query.get("page_size", [25])[0]),
            cursor_value(query.get("cursor", [None])[0]),
        )
        with self.db.connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM advisories a WHERE {clause}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT a.id,a.advisory_id,a.source,a.summary,a.severity,a.ecosystem,a.package_name,
                a.fixed_version,a.is_known_exploited,a.is_malicious_package,a.published_at,a.modified_at,a.first_seen_at
                FROM advisories a WHERE {clause} ORDER BY COALESCE(CAST(a.modified_at AS TEXT),CAST(a.published_at AS TEXT),'') DESC,a.id DESC LIMIT ? OFFSET ?""",
                params + [size, offset],
            ).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["aliases"] = [
                    r["alias_value"]
                    for r in conn.execute(
                        "SELECT alias_value FROM advisory_aliases WHERE advisory_pk=? ORDER BY alias_value",
                        (row["id"],),
                    ).fetchall()
                ]
                items.append(item)
        return page(items, total, offset, size) | {
            "source_freshness": self.sources(),
            "unit": "stored_advisory_records",
            "coverage_note": "동일 이슈의 패키지별 기록과 별칭이 포함될 수 있습니다. 전 세계 CVE 전체 건수가 아닙니다.",
        }

    def advisory_detail(self, user, identifier):
        try:
            result = self.app.get_advisory(identifier)
        except ValueError as exc:
            raise ApiError(404, "보안 정보를 찾을 수 없습니다.") from exc
        scope, params = self.scope_sql(user)
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""SELECT i.id,p.id AS project_id,p.name AS project_name,s.service_name,i.environment,i.risk_level,i.status
                FROM impacts i JOIN project_targets pt ON pt.service_pk=i.service_pk JOIN projects p ON p.id=pt.project_id
                JOIN services s ON s.id=i.service_pk WHERE i.advisory_pk=? AND {scope} ORDER BY i.updated_at DESC LIMIT 100""",
                [result["advisory"]["id"]] + params,
            ).fetchall()
        result["impacts"] = [dict(r) for r in rows]
        return result

    def findings(self, user, query):
        scope, params = self.scope_sql(
            user, project_id=query.get("project_id", [None])[0]
        )
        where = [scope]
        for key, col in (
            ("risk", "i.risk_level"),
            ("status", "i.status"),
            ("environment", "i.environment"),
        ):
            if query.get(key) and query[key][0]:
                where.append(col + "=?")
                params.append(query[key][0])
        if not query.get("status"):
            where.append("i.status IN ('open','acknowledged','in_progress')")
        if query.get("q") and query["q"][0]:
            like = "%" + query["q"][0].lower()[:200] + "%"
            where.append(
                "(lower(s.service_name) LIKE ? OR lower(i.package_name) LIKE ? OR lower(a.advisory_id) LIKE ? OR lower(a.summary) LIKE ?)"
            )
            params.extend([like] * 4)
        joins = """FROM impacts i JOIN services s ON s.id=i.service_pk JOIN advisories a ON a.id=i.advisory_pk
            JOIN project_targets pt ON pt.service_pk=i.service_pk JOIN projects p ON p.id=pt.project_id
            LEFT JOIN dependency_snapshots ds ON ds.id=s.latest_snapshot_id"""
        size, offset = (
            integer(query.get("page_size", [25])[0]),
            cursor_value(query.get("cursor", [None])[0]),
        )
        with self.db.connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c {joins} WHERE {' AND '.join(where)}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT i.*,s.service_name,s.freshness_threshold_seconds,ds.collected_at,ds.last_confirmed_at,a.advisory_id,a.source,a.summary,a.is_known_exploited,a.is_malicious_package,
                p.id AS project_id,p.name AS project_name,pt.id AS target_id {joins} WHERE {" AND ".join(where)}
                ORDER BY CASE i.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,i.updated_at DESC,i.id LIMIT ? OFFSET ?""",
                params + [size, offset],
            ).fetchall()
        fresh = all(s["status"] == "fresh" for s in self.sources())
        items = []
        for row in rows:
            item = dict(row)
            item["freshness_status"] = inventory_freshness(
                row["last_confirmed_at"] or row["collected_at"],
                row["environment"],
                row["freshness_threshold_seconds"],
            )
            stale = item["freshness_status"] != "fresh" or not fresh
            items.append(
                item
                | {
                    "assessment": "unknown" if stale else "confirmed",
                    "confidence_note": "보고된 패키지 버전 범위와 일치합니다. 수집이 오래됐다면 현재 상태는 재확인이 필요합니다.",
                    "data_stale": stale,
                }
            )
        return page(items, total, offset, size) | {
            "unit": "project_findings",
            "source_freshness": self.sources(),
        }

    def finding_detail(self, user, finding_id, write=False):
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT pt.project_id FROM impacts i JOIN project_targets pt ON pt.service_pk=i.service_pk WHERE i.id=?",
                (finding_id,),
            ).fetchone()
        if not row:
            raise ApiError(404, "영향 기록을 찾을 수 없습니다.")
        self.require_project(user, row["project_id"], write=write)
        return self.app.get_impact(finding_id)

    def overview(self, user, query):
        pid = query.get("project_id", [None])[0]
        projects = [p for p in self.projects(user) if not pid or p["id"] == pid]
        scope, params = self.scope_sql(user, project_id=pid)
        now = datetime.now(timezone.utc)
        with self.db.connect() as conn:
            rows = conn.execute(
                f"""SELECT i.*,p.id AS project_id,p.name AS project_name,s.service_name,a.advisory_id,a.summary,a.is_known_exploited,a.is_malicious_package
                FROM impacts i JOIN project_targets pt ON pt.service_pk=i.service_pk JOIN projects p ON p.id=pt.project_id
                JOIN services s ON s.id=i.service_pk JOIN advisories a ON a.id=i.advisory_pk WHERE {scope}""",
                params,
            ).fetchall()
            targets = conn.execute(
                f"""SELECT pt.id,s.environment,s.freshness_threshold_seconds,ds.collected_at,ds.last_confirmed_at FROM project_targets pt JOIN services s ON s.id=pt.service_pk
                LEFT JOIN dependency_snapshots ds ON ds.id=s.latest_snapshot_id WHERE {scope}""",
                params,
            ).fetchall()
        active = [dict(r) for r in rows if r["status"] in ACTIVE]
        cutoff = (now - timedelta(days=7)).isoformat()
        counts = {
            "projects": len(projects),
            "targets": len(targets),
            "open_findings": len(active),
            "unique_advisories": len({r["advisory_pk"] for r in active}),
            "critical": sum(r["risk_level"] == "critical" for r in active),
            "high": sum(r["risk_level"] == "high" for r in active),
            "new_7d": sum(str(r["first_detected_at"]) >= cutoff for r in active),
            "kev_malicious": sum(
                bool(r["is_known_exploited"] or r["is_malicious_package"])
                for r in active
            ),
            "stale_targets": sum(
                inventory_freshness(
                    r["last_confirmed_at"] or r["collected_at"],
                    r["environment"],
                    r["freshness_threshold_seconds"],
                )
                != "fresh"
                for r in targets
            ),
        }
        trend = []
        for n in range(29, -1, -1):
            day = (now - timedelta(days=n)).date().isoformat()
            trend.append(
                {
                    "date": day,
                    "new": sum(
                        str(r["first_detected_at"]).startswith(day) for r in rows
                    ),
                    "resolved": sum(
                        str(r["resolved_at"] or "").startswith(day) for r in rows
                    ),
                }
            )
        recent = self.advisory_search(user, {"page_size": ["5"]})
        return {
            "scope": {
                "project_id": pid,
                "project_name": self.require_project(user, pid)["name"]
                if pid
                else "내 전체 프로젝트",
            },
            "counts": counts,
            "project_risk": projects,
            "urgent_findings": sorted(
                active,
                key=lambda x: (
                    RANK.get(x["risk_level"], 5),
                    str(x["first_detected_at"]),
                ),
            )[:5],
            "recent_advisories": recent["items"],
            "trend": trend,
            "coverage": self.sources(),
            "as_of": utcnow(),
        }

    def alert_rule(self, user, pid, body=None):
        self.require_project(user, pid, owner=body is not None)
        if body is not None:
            risk = body.get("minimum_risk", "high")
            channel = body.get("channel_type", "webhook")
            target_url = str(body.get("target_url", "")).strip()
            if risk not in RANK or channel not in ("webhook", "slack_webhook"):
                raise ApiError(400, "알림 위험도 또는 채널 유형이 올바르지 않습니다.")
            if target_url and (
                urlparse(target_url).scheme != "https"
                or not urlparse(target_url).hostname
                or urlparse(target_url).username
            ):
                raise ApiError(
                    400, "알림 주소는 자격 증명이 포함되지 않은 HTTPS URL이어야 합니다."
                )
            with self.db.connect() as conn:
                conn.execute(
                    """INSERT INTO project_alert_rules(project_id,enabled,minimum_risk,channel_type,target_url,updated_at) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(project_id) DO UPDATE SET enabled=excluded.enabled,minimum_risk=excluded.minimum_risk,
                    channel_type=excluded.channel_type,target_url=excluded.target_url,updated_at=excluded.updated_at""",
                    (
                        pid,
                        int(bool(body.get("enabled", True))),
                        risk,
                        channel,
                        target_url,
                        utcnow(),
                    ),
                )
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM project_alert_rules WHERE project_id=?", (pid,)
            ).fetchone()
        return (
            dict(row)
            if row
            else {
                "enabled": 1,
                "minimum_risk": "high",
                "channel_type": "webhook",
                "target_url": "",
            }
        )

    def alert_events(self, user, query):
        scope, params = self.scope_sql(
            user, project_id=query.get("project_id", [None])[0]
        )
        size, offset = (
            integer(query.get("page_size", [25])[0]),
            cursor_value(query.get("cursor", [None])[0]),
        )
        joins = """FROM alert_events ae JOIN impacts i ON i.id=ae.impact_pk JOIN project_targets pt ON pt.service_pk=i.service_pk
            JOIN projects p ON p.id=pt.project_id JOIN services s ON s.id=i.service_pk"""
        with self.db.connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c {joins} WHERE {scope}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT ae.id,ae.reason,ae.status,ae.created_at,ae.sent_at,ae.retry_count,p.name AS project_name,
                s.service_name,i.package_name,i.risk_level {joins} WHERE {scope} ORDER BY ae.created_at DESC,ae.id LIMIT ? OFFSET ?""",
                params + [size, offset],
            ).fetchall()
        return page([dict(r) for r in rows], total, offset, size)

    def environment_candidates(self, user, pid):
        candidates = []
        for target in self.targets(user, pid):
            cpe = str(target["metadata"].get("cpe", ""))
            if not cpe.startswith("cpe:2.3:") or len(cpe.split(":")) < 6:
                continue
            # Product identifiers alone are evidence for review, not proof of applicability.
            parts = cpe.split(":")
            product = ":".join(parts[:5]) + ":"
            with self.db.connect() as conn:
                rows = conn.execute(
                    "SELECT id,advisory_id,summary,severity FROM advisories WHERE source='NVD' AND CAST(raw_payload AS TEXT) LIKE ? ORDER BY modified_at DESC LIMIT 30",
                    ("%" + product + "%",),
                ).fetchall()
            candidates += [
                dict(r)
                | {
                    "target_name": target["service_name"],
                    "environment": target["environment"],
                    "assessment": "potential",
                    "evidence": f"CPE 제품 식별자 일치: {product} — 버전·구성 조건 검토 필요",
                }
                for r in rows
            ]
        return {"items": candidates, "unit": "environment_review_candidates"}

    def route(self, request, method, path, query):
        try:
            return self._route(request, method, path, query)
        except ApiError as exc:
            return self.reply(request, {"error": exc.message}, exc.status)
        except ValueError as exc:
            return self.reply(request, {"error": str(exc)}, 400)

    def _route(self, request, method, path, query):
        parts = [unquote(x) for x in path.split("/") if x][2:]
        if parts == ["auth", "session"] and method == "GET":
            user = self.session_user(request, False)
            return self.reply(
                request, {"user": user, "auth_mode": self.app.settings.auth_mode}
            )
        if parts in (["auth", "login"], ["auth", "setup"]) and method == "POST":
            self.check_origin(request)
            ip_key = digest("auth-ip:" + self.client_address(request))
            now = datetime.now(timezone.utc)
            cutoff = (now - timedelta(minutes=15)).isoformat()
            with self.db.connect() as conn:
                attempt = conn.execute(
                    "SELECT attempts,window_start FROM workspace_login_attempts WHERE attempt_key=?",
                    (ip_key,),
                ).fetchone()
                if (
                    attempt
                    and str(attempt["window_start"]) > cutoff
                    and attempt["attempts"] >= 50
                ):
                    raise ApiError(
                        429, "로그인 요청이 많습니다. 잠시 후 다시 시도해 주세요."
                    )
                conn.execute(
                    """INSERT INTO workspace_login_attempts(attempt_key,attempts,window_start) VALUES(?,1,?)
                    ON CONFLICT(attempt_key) DO UPDATE SET attempts=CASE WHEN workspace_login_attempts.window_start<? THEN 1 ELSE workspace_login_attempts.attempts+1 END,
                    window_start=CASE WHEN workspace_login_attempts.window_start<? THEN excluded.window_start ELSE workspace_login_attempts.window_start END""",
                    (ip_key, now.isoformat(), cutoff, cutoff),
                )
            body = self.app.read_json(request, max_length=16384)
            cookie = (
                self.login(request, body)
                if parts[-1] == "login"
                else self.new_session(self.setup(body))
            )
            return self.reply(request, {"ok": True}, cookie=cookie)
        user = self.session_user(request)
        if method != "GET":
            self.csrf(request, user)
        body = (
            self.app.read_json(
                request, max_length=self.app.settings.max_snapshot_payload_bytes
            )
            if method != "GET"
            else {}
        )
        if parts == ["auth", "logout"] and method == "POST":
            with self.db.connect() as conn:
                conn.execute(
                    "DELETE FROM workspace_sessions WHERE user_id=? AND csrf_token=?",
                    (user["id"], user["csrf_token"]),
                )
            return self.reply(
                request,
                {"ok": True},
                cookie=f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            )
        if parts == ["me"] and method == "GET":
            return self.reply(request, {"user": user, "projects": self.projects(user)})
        if parts == ["intel", "sources"] and method == "GET":
            return self.reply(request, {"items": self.sources(), "as_of": utcnow()})
        if parts in (["intel", "advisories"], ["intel", "records"]) and method == "GET":
            return self.reply(request, self.advisory_search(user, query))
        if len(parts) == 3 and parts[:2] == ["intel", "advisories"] and method == "GET":
            return self.reply(request, self.advisory_detail(user, parts[2]))
        if len(parts) == 4 and parts[:2] == ["intel", "records"] and method == "GET":
            result = self.advisory_detail(user, parts[3])
            if result["advisory"]["source"] != parts[2]:
                raise ApiError(404, "기록을 찾을 수 없습니다.")
            return self.reply(request, result)
        if parts == ["overview"] and method == "GET":
            return self.reply(request, self.overview(user, query))
        if parts == ["projects"]:
            if method == "GET":
                return self.reply(request, {"items": self.projects(user)})
            if method == "POST":
                return self.reply(request, self.create_project(user, body), 201)
        if parts == ["findings"] and method == "GET":
            return self.reply(request, self.findings(user, query))
        if len(parts) == 2 and parts[0] == "findings":
            result = self.finding_detail(user, parts[1], write=method != "GET")
            if method == "GET":
                return self.reply(request, result)
            if method == "PATCH":
                if body.get("status") == "accepted_risk" and not user["is_admin"]:
                    raise ApiError(403, "위험 수용에는 관리자 승인이 필요합니다.")
                allowed = {
                    k: v
                    for k, v in body.items()
                    if k in ("status", "reason", "expires_at")
                }
                return self.reply(
                    request,
                    self.app.update_impact_status(
                        parts[1], allowed | {"actor": user["email"]}
                    ),
                )
        if len(parts) >= 2 and parts[0] == "projects":
            pid = parts[1]
            if len(parts) == 2:
                project = self.require_project(user, pid, write=method != "GET")
                if method == "GET":
                    return self.reply(request, project)
                if method == "PATCH":
                    status = body.get("status", project["status"])
                    if status not in ("active", "archived"):
                        raise ApiError(400, "잘못된 프로젝트 상태입니다.")
                    with self.db.connect() as conn:
                        conn.execute(
                            "UPDATE projects SET name=?,description=?,status=?,updated_at=? WHERE id=?",
                            (
                                text(body, "name", 100),
                                text(body, "description", 2000, False),
                                status,
                                utcnow(),
                                pid,
                            ),
                        )
                    return self.reply(request, self.require_project(user, pid))
            if len(parts) == 3 and parts[2] == "targets":
                if method == "GET":
                    return self.reply(request, {"items": self.targets(user, pid)})
                if method == "POST":
                    return self.reply(request, self.create_target(user, pid, body), 201)
            if len(parts) == 4 and parts[2] == "targets":
                target = self.target(user, pid, parts[3], write=method != "GET")
                if method == "GET":
                    return self.reply(
                        request,
                        self.app.get_service_detail(target["service_id"])
                        | {
                            "target": target
                            | {"metadata": json_column(target["metadata"], {})}
                        },
                    )
                if method == "PATCH":
                    metadata = body.get("metadata", json_column(target["metadata"], {}))
                    if (
                        not isinstance(metadata, dict)
                        or len(json.dumps(metadata)) > 10000
                    ):
                        raise ApiError(400, "잘못된 환경 정보입니다.")
                    name = str(body.get("name", target["service_name"])).strip()
                    mode = body.get("collection_mode", target["collection_mode"])
                    endpoint = body.get(
                        "status_endpoint_url", target["status_endpoint_url"]
                    )
                    if not name or len(name) > 100 or mode not in ("push", "poll"):
                        raise ApiError(400, "잘못된 대상 설정입니다.")
                    if endpoint and urlparse(endpoint).scheme not in ("https", "http"):
                        raise ApiError(400, "Endpoint는 HTTP(S) URL이어야 합니다.")
                    with self.db.connect() as conn:
                        conn.execute(
                            "UPDATE project_targets SET metadata=? WHERE id=?",
                            (json.dumps(metadata), target["id"]),
                        )
                        conn.execute(
                            "UPDATE services SET service_name=?,collection_mode=?,status_endpoint_url=?,updated_at=? WHERE id=?",
                            (name, mode, endpoint, utcnow(), target["service_pk"]),
                        )
                    return self.reply(request, {"ok": True})
            if (
                len(parts) == 5
                and parts[2] == "targets"
                and parts[4] in ("snapshots", "credentials")
                and method == "POST"
            ):
                target = self.target(user, pid, parts[3], write=True)
                if parts[4] == "credentials":
                    return self.reply(
                        request,
                        self.app.create_push_credential(
                            target["service_id"], {"environment": target["environment"]}
                        ),
                        201,
                    )
                return self.reply(
                    request,
                    self.app.push_snapshot(
                        body
                        | {
                            "service_id": target["service_id"],
                            "environment": target["environment"],
                        }
                    ),
                    201,
                )
            if len(parts) == 3 and parts[2] == "inventory" and method == "GET":
                return self.reply(request, self.inventory(user, pid, query))
            if (
                len(parts) == 3
                and parts[2] == "environment-candidates"
                and method == "GET"
            ):
                return self.reply(request, self.environment_candidates(user, pid))
            if (
                len(parts) == 3
                and parts[2] == "alert-rules"
                and method in ("GET", "PATCH")
            ):
                return self.reply(
                    request,
                    self.alert_rule(user, pid, body if method == "PATCH" else None),
                )
            if len(parts) == 3 and parts[2] == "members":
                self.require_project(user, pid, owner=method != "GET")
                if method == "GET":
                    with self.db.connect() as conn:
                        rows = conn.execute(
                            "SELECT u.id,u.email,u.display_name,m.role FROM project_memberships m JOIN workspace_users u ON u.id=m.user_id WHERE m.project_id=? ORDER BY u.email",
                            (pid,),
                        ).fetchall()
                    return self.reply(request, {"items": [dict(r) for r in rows]})
                if method == "POST":
                    email = email_value(body.get("email"))
                    role = body.get("role", "viewer")
                    if role not in ("owner", "maintainer", "viewer"):
                        raise ApiError(400, "잘못된 역할입니다.")
                    with self.db.connect() as conn:
                        member = conn.execute(
                            "SELECT id FROM workspace_users WHERE email=?", (email,)
                        ).fetchone()
                        if not member:
                            raise ApiError(
                                400, "먼저 관리자가 계정 초대 링크를 발급해야 합니다."
                            )
                        previous = conn.execute(
                            "SELECT role FROM project_memberships WHERE project_id=? AND user_id=?",
                            (pid, member["id"]),
                        ).fetchone()
                        if (
                            previous
                            and previous["role"] == "owner"
                            and role != "owner"
                            and conn.execute(
                                "SELECT COUNT(*) AS c FROM project_memberships WHERE project_id=? AND role='owner'",
                                (pid,),
                            ).fetchone()["c"]
                            <= 1
                        ):
                            raise ApiError(
                                409, "프로젝트에 소유자가 한 명 이상 있어야 합니다."
                            )
                        conn.execute(
                            "INSERT INTO project_memberships(project_id,user_id,role) VALUES(?,?,?) ON CONFLICT(project_id,user_id) DO UPDATE SET role=excluded.role",
                            (pid, member["id"], role),
                        )
                    return self.reply(request, {"ok": True})
        if parts == ["alert-events"] and method == "GET":
            return self.reply(request, self.alert_events(user, query))
        if parts and parts[0] == "admin":
            if not user["is_admin"]:
                raise ApiError(403, "관리자 권한이 필요합니다.")
            if parts == ["admin", "invitations"] and method == "POST":
                email = email_value(body.get("email"))
                token = self.make_setup_token(email)
                return self.reply(
                    request,
                    {
                        "setup_fragment": "#setup=" + token,
                        "email": email,
                        "expires_in_hours": 24,
                    },
                    201,
                )
            if parts == ["admin", "unassigned-targets"] and method == "GET":
                with self.db.connect() as conn:
                    rows = conn.execute(
                        "SELECT s.id,s.service_id,s.service_name,s.environment FROM services s LEFT JOIN project_targets pt ON pt.service_pk=s.id WHERE pt.id IS NULL ORDER BY s.service_name"
                    ).fetchall()
                return self.reply(request, {"items": [dict(r) for r in rows]})
            if parts == ["admin", "assign-target"] and method == "POST":
                pid = text(body, "project_id")
                self.require_project(user, pid, owner=True)
                sid = text(body, "service_pk")
                tid = str(uuid.uuid4())
                with self.db.connect() as conn:
                    if not conn.execute(
                        "SELECT id FROM services WHERE id=?", (sid,)
                    ).fetchone():
                        raise ApiError(404, "서비스가 없습니다.")
                    if conn.execute(
                        "SELECT id FROM project_targets WHERE service_pk=?", (sid,)
                    ).fetchone():
                        raise ApiError(409, "이미 연결된 서비스입니다.")
                    conn.execute(
                        "INSERT INTO project_targets(id,project_id,service_pk,target_key,created_at) VALUES(?,?,?,?,?)",
                        (tid, pid, sid, tid, utcnow()),
                    )
                return self.reply(request, {"ok": True}, 201)
        raise ApiError(404, "API를 찾을 수 없습니다.")
