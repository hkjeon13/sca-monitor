import json
import threading
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

import pytest

from backend.sca_monitor.alert_dispatch import dispatch_pending_alerts
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import Settings
from backend.sca_monitor.workspace import ApiError, password_hash, password_matches


@pytest.fixture
def workspace(tmp_path):
    settings = Settings(
        app_env="test",
        host="127.0.0.1",
        port=0,
        data_dir=tmp_path,
        database_url=str(tmp_path / "workspace.sqlite3"),
        database_path=tmp_path / "workspace.sqlite3",
        frontend_dir=Path("frontend").resolve(),
        smoke_token="test",
        auth_mode="local",
    )
    app = ScaMonitorApp(settings)
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield app, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


class Client:
    def __init__(self, url):
        self.url = url
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))
        self.csrf = ""

    def request(self, path, method="GET", body=None, csrf=True, headers=None):
        hdr = {
            "Content-Type": "application/json",
            **({"X-CSRF-Token": self.csrf} if csrf else {}),
            **(headers or {}),
        }
        req = Request(
            self.url + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers=hdr,
        )
        try:
            with self.opener.open(req, timeout=10) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def setup(self, app, email, admin=False):
        token = app.workspace.make_setup_token(
            email if not admin else None, admin=admin
        )
        status, result = self.request(
            "/api/v2/auth/setup",
            "POST",
            {
                "token": token,
                "email": email,
                "display_name": email.split("@")[0],
                "password": "A-long-test-password-2026",
            },
        )
        assert status == 200, result
        self.csrf = self.request("/api/v2/auth/session")[1]["user"]["csrf_token"]


def test_password_hash_and_one_time_setup(workspace):
    app, url = workspace
    hashed = password_hash("A-long-test-password-2026")
    assert password_matches("A-long-test-password-2026", hashed)
    assert not password_matches("wrong", hashed)
    with pytest.raises(ApiError):
        password_hash("short")
    client = Client(url)
    token = app.workspace.make_setup_token(admin=True)
    body = {
        "token": token,
        "email": "admin@example.com",
        "display_name": "Admin",
        "password": "A-long-test-password-2026",
    }
    assert client.request("/api/v2/auth/setup", "POST", body)[0] == 200
    assert client.request("/api/v2/auth/setup", "POST", body)[0] == 400
    assert Client(url).request("/api/v2/projects")[0] == 401
    assert Client(url).request("/api/v1/services")[0] == 401
    assert (
        Client(url).request("/api/v1/snapshots", "POST", {"service_id": "forged"})[0]
        == 401
    )


def test_project_isolation_csrf_and_roles(workspace):
    app, url = workspace
    admin = Client(url)
    admin.setup(app, "admin@example.com", True)
    alice = Client(url)
    alice.setup(app, "alice@example.com")
    bob = Client(url)
    bob.setup(app, "bob@example.com")
    assert (
        alice.request("/api/v2/projects", "POST", {"name": "A"}, csrf=False)[0] == 403
    )
    status, project = alice.request(
        "/api/v2/projects", "POST", {"name": "Alice project"}
    )
    assert status == 201
    pid = project["id"]
    assert bob.request("/api/v2/projects")[1]["items"] == []
    assert bob.request("/api/v2/projects/" + pid)[0] == 404
    assert bob.request("/api/v1/overview")[0] == 403
    status, target = alice.request(
        f"/api/v2/projects/{pid}/targets",
        "POST",
        {"name": "payment", "environment": "prod"},
    )
    assert status == 201, target
    tid = target["id"]
    assert (
        bob.request(f"/api/v2/projects/{pid}/targets/{tid}/credentials", "POST", {})[0]
        == 404
    )
    assert (
        alice.request(
            f"/api/v2/projects/{pid}/members",
            "POST",
            {"email": "bob@example.com", "role": "viewer"},
        )[0]
        == 200
    )
    assert bob.request("/api/v2/projects/" + pid)[0] == 200
    assert (
        bob.request(f"/api/v2/projects/{pid}/targets", "POST", {"name": "bad"})[0]
        == 403
    )
    assert (
        alice.request(
            f"/api/v2/projects/{pid}/members",
            "POST",
            {"email": "alice@example.com", "role": "viewer"},
        )[0]
        == 409
    )
    assert (
        bob.request(
            f"/api/v2/projects/{pid}/alert-rules",
            "PATCH",
            {"target_url": "https://example.com"},
        )[0]
        == 403
    )
    assert (
        alice.request(
            f"/api/v2/projects/{pid}/alert-rules",
            "PATCH",
            {"target_url": "http://example.com"},
        )[0]
        == 400
    )
    assert (
        alice.request(
            f"/api/v2/projects/{pid}/targets/{tid}/snapshots",
            "POST",
            {
                "dependencies": [
                    {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
                ]
            },
        )[0]
        == 201
    )
    findings = alice.request("/api/v2/findings")[1]
    assert findings["total"] > 0
    f = findings["items"][0]
    assert f["project_id"] == pid and f["service_name"] == "payment"
    outsider = Client(url)
    outsider.setup(app, "outsider@example.com")
    assert outsider.request("/api/v2/findings")[1]["total"] == 0
    assert outsider.request("/api/v2/findings/" + f["id"])[0] == 404
    assert (
        bob.request(
            "/api/v2/findings/" + f["id"],
            "PATCH",
            {"status": "fixed", "reason": "test"},
        )[0]
        == 403
    )
    assert (
        alice.request(
            "/api/v2/findings/" + f["id"],
            "PATCH",
            {"status": "acknowledged", "reason": "reviewed"},
        )[0]
        == 200
    )
    assert alice.request(f"/api/v2/projects/{pid}/inventory")[1]["total"] == 1
    overview = alice.request("/api/v2/overview")[1]
    assert (
        overview["counts"]["projects"] == 1 and overview["counts"]["open_findings"] > 0
    )
    # Browser credentials cannot authorize cross-target snapshot pushes.
    token = alice.request(
        f"/api/v2/projects/{pid}/targets/{tid}/credentials", "POST", {}
    )[1]["token"]
    assert Client(url).request(
        "/api/v1/snapshots",
        "POST",
        {
            "service_id": "another",
            "dependencies": [
                {"ecosystem": "npm", "name": "lodash", "version": "1.0.0"}
            ],
        },
        headers={"Authorization": "Bearer " + token},
    )[0] in (400, 403)
    # Findings create an in-app outbox entry but cannot fall through to a global channel.
    result = dispatch_pending_alerts(
        app, webhook_url="https://example.com", dry_run=True
    )
    assert result.pending == 0


def test_search_pagination_aliases_and_detail_privacy(workspace):
    app, url = workspace
    admin = Client(url)
    admin.setup(app, "admin@example.com", True)
    with app.db.connect() as conn:
        for n in range(205):
            conn.execute(
                """INSERT INTO advisories(id,advisory_id,source,summary,severity,ecosystem,package_name,canonical_package_name,affected_versions,raw_payload,modified_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f"test-{n}",
                    f"CVE-2099-{n:04d}",
                    "NVD",
                    "Test search record",
                    "high",
                    "npm",
                    "search-package",
                    "search-package",
                    "[]",
                    "{}",
                    "2099-01-01",
                ),
            )
    first = admin.request("/api/v2/intel/advisories?source=NVD&page_size=100")[1]
    assert first["total"] == 205 and len(first["items"]) == 100 and first["next_cursor"]
    second = admin.request(
        "/api/v2/intel/advisories?source=NVD&page_size=100&cursor="
        + first["next_cursor"]
    )[1]
    assert not {r["id"] for r in first["items"]} & {r["id"] for r in second["items"]}
    assert admin.request("/api/v2/intel/advisories?q=CVE-2099-0001")[1]["total"] == 1
    assert admin.request("/api/v2/intel/advisories?source=invalid")[0] == 400
    assert admin.request("/api/v2/intel/advisories?cursor=invalid")[0] == 400
    detail = admin.request("/api/v2/intel/advisories/test-1")[1]
    assert detail["advisory"]["source"] == "NVD"
    assert admin.request("/api/v2/intel/records/OSV/test-1")[0] == 404
    assert any(
        s["source"] == "NVD" and s["stored_count"] == 205
        for s in admin.request("/api/v2/intel/sources")[1]["items"]
    )


def test_login_logout_reset_and_origin(workspace):
    app, url = workspace
    admin = Client(url)
    admin.setup(app, "admin@example.com", True)
    login = Client(url)
    assert (
        login.request(
            "/api/v2/auth/login",
            "POST",
            {"email": "admin@example.com", "password": "wrong"},
        )[0]
        == 401
    )
    assert (
        login.request(
            "/api/v2/auth/login",
            "POST",
            {"email": "admin@example.com", "password": "A-long-test-password-2026"},
            headers={"Origin": "https://evil.example"},
        )[0]
        == 403
    )
    assert (
        login.request(
            "/api/v2/auth/login",
            "POST",
            {"email": "admin@example.com", "password": "A-long-test-password-2026"},
        )[0]
        == 200
    )
    login.csrf = login.request("/api/v2/auth/session")[1]["user"]["csrf_token"]
    assert login.request("/api/v2/auth/logout", "POST", {})[0] == 200
    assert login.request("/api/v2/projects")[0] == 401
    reset = app.workspace.make_setup_token("admin@example.com")
    assert (
        Client(url).request(
            "/api/v2/auth/setup",
            "POST",
            {
                "token": reset,
                "email": "admin@example.com",
                "display_name": "Admin",
                "password": "New-long-password-2026",
            },
        )[0]
        == 200
    )
    assert admin.request("/api/v2/projects")[0] == 401


def test_project_alert_policy_and_actual_routing(workspace):
    app, url = workspace
    client = Client(url)
    client.setup(app, "admin@example.com", True)
    pid = client.request("/api/v2/projects", "POST", {"name": "Alerts"})[1]["id"]
    target = client.request(
        f"/api/v2/projects/{pid}/targets", "POST", {"name": "payment"}
    )[1]
    client.request(
        f"/api/v2/projects/{pid}/targets/{target['id']}/snapshots",
        "POST",
        {
            "dependencies": [
                {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
            ]
        },
    )
    client.request(
        f"/api/v2/projects/{pid}/alert-rules",
        "PATCH",
        {"minimum_risk": "critical", "target_url": "https://project.example/hook"},
    )
    assert (
        dispatch_pending_alerts(
            app, webhook_url=None, project_only=True, dry_run=True
        ).pending
        == 0
    )
    client.request(
        f"/api/v2/projects/{pid}/alert-rules",
        "PATCH",
        {"minimum_risk": "high", "target_url": "https://project.example/hook"},
    )
    calls = []
    result = dispatch_pending_alerts(
        app,
        webhook_url="https://global.example/hook",
        project_only=True,
        sender=lambda url, payload, headers: calls.append((url, payload)),
    )
    assert result.sent == 1 and calls[0][0] == "https://project.example/hook"
    assert client.request("/api/v2/alert-events")[1]["items"][0]["status"] == "sent"
    with app.db.connect() as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) AS c FROM audit_logs WHERE actor='admin@example.com' AND action='workspace.patch'"
            ).fetchone()["c"]
            >= 2
        )
    cookie = app.workspace.new_session(
        client.request("/api/v2/auth/session")[1]["user"]["id"]
    )
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_inventory_age_is_calculated_at_read_time(workspace):
    app, url = workspace
    client = Client(url)
    client.setup(app, "admin@example.com", True)
    pid = client.request("/api/v2/projects", "POST", {"name": "Aging"})[1]["id"]
    target = client.request(
        f"/api/v2/projects/{pid}/targets", "POST", {"name": "old snapshot"}
    )[1]
    client.request(
        f"/api/v2/projects/{pid}/targets/{target['id']}/snapshots",
        "POST",
        {
            "dependencies": [
                {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
            ]
        },
    )
    with app.db.connect() as conn:
        conn.execute(
            "UPDATE dependency_snapshots SET collected_at='2000-01-01T00:00:00+00:00',last_confirmed_at='2000-01-01T00:00:00+00:00'"
        )
    assert (
        client.request(f"/api/v2/projects/{pid}/targets")[1]["items"][0][
            "freshness_status"
        ]
        == "stale"
    )
    assert client.request("/api/v2/overview")[1]["counts"]["stale_targets"] == 1
    assert client.request("/api/v2/findings")[1]["items"][0]["assessment"] == "unknown"


def test_setup_and_session_are_atomic_when_session_write_fails(workspace):
    app, url = workspace
    client = Client(url)
    token = app.workspace.make_setup_token(admin=True)
    with app.db.connect() as conn:
        conn.execute(
            "CREATE TRIGGER fail_session BEFORE INSERT ON workspace_sessions BEGIN SELECT RAISE(ABORT, 'test session failure'); END"
        )
    status, _ = client.request(
        "/api/v2/auth/setup",
        "POST",
        {
            "token": token,
            "email": "atomic@example.test",
            "display_name": "Atomic",
            "password": "Atomic-test-password-2026!",
        },
    )
    assert status == 500
    with app.db.connect() as conn:
        assert (
            conn.execute("SELECT COUNT(*) AS c FROM workspace_users").fetchone()["c"]
            == 0
        )
        assert (
            conn.execute("SELECT used_at FROM workspace_setup_tokens").fetchone()[
                "used_at"
            ]
            is None
        )


def test_background_import_waits_for_interactive_write(workspace):
    from backend.sca_monitor.coordination import interactive_write

    app, _ = workspace
    entered = threading.Event()
    done = threading.Event()

    def background():
        entered.set()
        app.import_osv_payload(
            {
                "id": "OSV-PRIORITY-TEST",
                "modified": "2026-10-28T00:00:00Z",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "priority-test"},
                        "versions": ["1.0.0"],
                    }
                ],
            }
        )
        done.set()

    with interactive_write(app.settings.data_dir):
        thread = threading.Thread(target=background)
        thread.start()
        assert entered.wait(2)
        assert not done.wait(0.1)
    assert done.wait(5)
    thread.join()
