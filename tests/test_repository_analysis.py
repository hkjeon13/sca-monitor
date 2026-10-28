import io
import json
import tarfile
import uuid

import pytest

from test_workspace import workspace, Client
from backend.sca_monitor.repository.scanner import analyze_archive, redact
from backend.sca_monitor.repository.transport import repository_url, RepositoryError
from backend.sca_monitor.repository.worker import RepositoryWorker


def archive(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        root = tarfile.TarInfo("fixture"); root.type = tarfile.DIRTYPE; tar.addfile(root)
        for name, content in files.items():
            raw = content.encode()
            entry = tarfile.TarInfo("fixture/" + name); entry.size = len(raw)
            tar.addfile(entry, io.BytesIO(raw))
    return out.getvalue()


def analyze(files):
    return analyze_archive(archive(files), str(uuid.uuid4()))[0]


def test_custom_requirements_constraints_and_includes():
    result = analyze({
        "Makefile": "setup:\n\tpip install -r deps/backend.list\n",
        "deps/backend.list": "-r base.txt\n-c ../requirements.constraints.txt\nrequests\n",
        "deps/base.txt": "urllib3==2.2.3\n-r backend.list\n",
        "requirements.constraints.txt": "requests==2.32.3\nuninstalled==9.0\n",
        ".env": "PRIVATE_TOKEN=hidden",
    })
    packages = {(c["name"], c["version"]) for c in result["components"]}
    assert packages == {("requests", "2.32.3"), ("urllib3", "2.2.3")}
    assert any(g["reason"] == "requirements_include_cycle" for g in result["gaps"])
    assert not any(e["file"] == ".env" for c in result["components"] for e in c["evidence"])


def test_toml_lock_graph_and_npm_multiple_paths():
    result = analyze({
        "pyproject.toml": '[project]\ndependencies=["requests>=2"]\n',
        "uv.lock": '[[package]]\nname="requests"\nversion="2.32.3"\ndependencies=[{name="urllib3"}]\n[[package]]\nname="urllib3"\nversion="2.2.3"\n',
        "web/package.json": json.dumps({"dependencies": {"a": "^1.0.0", "b": "1.0.0"}}),
        "web/package-lock.json": json.dumps({"packages": {"": {"dependencies": {"a": "^1", "b": "1"}}, "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "1"}}, "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "1"}}, "node_modules/c": {"version": "1.0.0"}}}),
    })
    by_name = {c["name"]: c for c in result["components"]}
    assert len(result["components"]) == 5
    assert by_name["requests"]["relationship"] == "direct"
    assert by_name["urllib3"]["relationship"] == "transitive"
    assert (by_name["a"]["id"], by_name["c"]["id"]) in result["edges"]
    assert (by_name["b"]["id"], by_name["c"]["id"]) in result["edges"]


def test_archive_traversal_rejected_and_secrets_redacted():
    with pytest.raises(ValueError): analyze({"../../escape": "bad"})
    assert "secret-value" not in redact('{"api_key": "secret-value"}')
    assert "ghp_" not in redact('x="ghp_' + 'a' * 30 + '"')
    result = analyze({"setup.py": 'import os\nos.system("pip install hidden-package")', "Dockerfile": "FROM ubuntu:24.04\nRUN apt-get install libexample\n"})
    assert result["installation_candidates"]
    assert not result["components"]
    assert result["images"][0]["status"] == "contents_not_scanned"


def test_repository_private_credentials_permissions_and_immutable_report(workspace, monkeypatch):
    app, url = workspace
    admin, outsider = Client(url), Client(url)
    admin.setup(app, "admin@example.test", True)
    outsider.setup(app, "outsider@example.test")
    pid = admin.request("/api/v2/projects", "POST", {"name": "Repository"})[1]["id"]
    base = f"/api/v2/projects/{pid}"
    status, credential = admin.request(base + "/repository-credentials", "POST", {"label": "private", "repository_url": "https://github.com/example/repo", "username": "private-user", "secret": "private-secret"})
    assert status == 201
    with app.db.connect() as c:
        encrypted = c.execute("SELECT encrypted_value FROM repository_credentials WHERE id=?", (credential["id"],)).fetchone()["encrypted_value"]
    assert "private-secret" not in encrypted and "private-user" not in encrypted
    assert admin.request(base + "/repository-credentials/" + credential["id"], "PATCH", {"label": "changed-host", "repository_url": "https://gitlab.com/example/repo", "secret": "another-secret"})[0] == 400
    assert outsider.request(base + "/repositories")[0] == 404
    status, repo = admin.request(base + "/repositories", "POST", {"url": "https://github.com/example/repo", "credential_id": credential["id"]})
    assert status == 201
    sid = repo["scan"]["id"]
    assert outsider.request(base + f"/repository-scans/{sid}/report")[0] == 404
    content = archive({"requirements.dev.txt": "requests==2.32.3\n", "Dockerfile": "FROM python:3.12\n"})
    calls = []
    def fetch(snapshot, secret):
        calls.append(secret); return "a" * 40, content
    worker = RepositoryWorker(app, fetcher=fetch)
    worker.run_once()
    report = admin.request(base + f"/repository-scans/{sid}/report")[1]
    assert report["report"]["component_count"] == 1
    assert report["report"]["execution_performed"] is False
    assert calls[0] == {"username": "private-user", "secret": "private-secret"}
    components = admin.request(base + f"/repository-scans/{sid}/components")[1]
    assert components["items"][0]["name"] == "requests"
    assert app.workspace.inventory({"id": "unused", "is_admin": True}, pid, {})["total"] == 1
    (app.settings.data_dir / "sandbox-ready.json").write_text("{}")
    real_capabilities = app.workspace.repositories.capabilities
    monkeypatch.setattr(app.workspace.repositories, "capabilities", lambda: real_capabilities() | {"deep_analysis": True})
    key = str(uuid.uuid4())
    request = {"profile": "python", "idempotency_key": key}
    status, deep = admin.request(base + f"/repository-scans/{sid}/deep-analysis", "POST", request)
    assert status == 202
    assert admin.request(base + f"/repository-scans/{sid}/deep-analysis", "POST", request)[1]["id"] == deep["id"]
    assert outsider.request(base + f"/repository-scans/{sid}/deep-analysis", "POST", request)[0] == 404
    worker.sandbox = lambda *args: {"completed": True, "sboms": [], "gaps": []}
    worker.run_once()
    after = admin.request(base + f"/repository-scans/{sid}/report")[1]
    assert after["report"] == report["report"]
    assert admin.request(base + f"/repository-scans/{deep['id']}/report")[1]["report"]["comparison"]["parent_id"] == sid
    with app.db.connect() as c:
        c.execute("UPDATE repository_connections SET last_checked_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", repo["id"]))
    worker.schedule_due()
    with app.db.connect() as c:
        jobs = c.execute("SELECT mode FROM repository_scan_runs WHERE status='queued'").fetchall()
    assert jobs and all(row["mode"] == "preliminary" for row in jobs)


def test_partial_inventory_retains_old_versions_and_marks_them_stale(workspace):
    app, url = workspace
    admin = Client(url); admin.setup(app, "owner@example.test", True)
    pid = admin.request("/api/v2/projects", "POST", {"name": "Preservation"})[1]["id"]
    base = f"/api/v2/projects/{pid}"
    repo = admin.request(base + "/repositories", "POST", {"url": "https://github.com/example/preserve"})[1]
    content = [archive({"requirements.txt": "requests==2.30.0\n"})]
    worker = RepositoryWorker(app, fetcher=lambda *args: ("a" * 40, content[0]))
    worker.run_once()
    content[0] = archive({"requirements.txt": "requests==2.32.3\n"})
    admin.request(base + f"/repositories/{repo['id']}/scans", "POST", {"idempotency_key": str(uuid.uuid4())})
    worker.run_once()
    items = app.workspace.inventory({"id": "unused", "is_admin": True}, pid, {})["items"]
    assert {x["resolved_version"] for x in items} == {"2.30.0", "2.32.3"}
    old = next(x for x in items if x["resolved_version"] == "2.30.0")
    assert old["source"].startswith("retained:") and old["freshness_status"] == "stale"
    content[0] = archive({"README.md": "No supported manifest"})
    admin.request(base + f"/repositories/{repo['id']}/scans", "POST", {"idempotency_key": str(uuid.uuid4())})
    worker.run_once()
    assert app.workspace.inventory({"id": "unused", "is_admin": True}, pid, {})["total"] == 2


def test_openrouter_settings_encrypted_and_admin_only(workspace):
    app, url = workspace
    admin, member = Client(url), Client(url)
    admin.setup(app, "admin@example.test", True); member.setup(app, "member@example.test")
    endpoint = "/api/v2/admin/repository-analysis/settings"
    assert member.request(endpoint)[0] == 403
    secret = "sk-or-test-" + "x" * 32
    status, result = admin.request(endpoint, "POST", {"api_key": secret})
    assert status == 200 and result["llm"]["configured"]
    assert secret not in json.dumps(admin.request(endpoint)[1])
    with app.db.connect() as c:
        assert secret not in c.execute("SELECT encrypted_key FROM repository_llm_settings").fetchone()["encrypted_key"]
    assert app.workspace.repositories.llm_key() == secret


def test_docker_platform_and_stage_aliases_are_preserved():
    result = analyze({"Dockerfile": "ARG BASE=python:3.12\nFROM --platform=linux/arm64 ${BASE} AS build\nFROM build AS final\n"})
    assert len(result["images"]) == 1
    assert result["images"][0]["requested_platform"] == "linux/arm64"
    assert result["images"][0]["reference"] == "python:3.12"


def test_cancelled_deep_analysis_keeps_checkpoint_and_original_report(workspace, monkeypatch):
    from backend.sca_monitor.repository.worker import Cancelled
    from backend.sca_monitor.repository.sandbox import redact_document
    app, url = workspace
    admin = Client(url); admin.setup(app, "admin@example.test", True)
    pid = admin.request("/api/v2/projects", "POST", {"name": "Cancellation"})[1]["id"]
    base = f"/api/v2/projects/{pid}"
    repo = admin.request(base + "/repositories", "POST", {"url": "https://github.com/example/cancel"})[1]
    worker = RepositoryWorker(app, fetcher=lambda *args: ("c" * 40, archive({"requirements.txt": "idna==3.10\n"})))
    worker.run_once()
    sid = repo["scan"]["id"]
    original = admin.request(base + f"/repository-scans/{sid}/report")[1]["report"]
    monkeypatch.setattr(app.workspace.repositories, "capabilities", lambda: {"deep_analysis": True})
    deep = admin.request(base + f"/repository-scans/{sid}/deep-analysis", "POST", {"profile": "python", "idempotency_key": str(uuid.uuid4())})[1]
    def cancelled(job, snapshot, source, heartbeat):
        partial = {"sboms": [], "steps": [{"tail": "token=secret-value"}], "project_execution_performed": True}
        (source.parent / "sandbox-partial.json").write_text(json.dumps(redact_document(partial)))
        raise Cancelled()
    worker.sandbox = cancelled
    worker.run_once()
    result = admin.request(base + f"/repository-scans/{deep['id']}/report")[1]
    assert result["scan"]["status"] == "cancelled" and result["report"]["runtime"]["steps"]
    assert "secret-value" not in json.dumps(result)
    assert admin.request(base + f"/repository-scans/{sid}/report")[1]["report"] == original


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://127.0.0.1/a/b", "https://user:token@github.com/a/b", "https://github.com/a/b?token=x", "https://github.com/a/../b", "https://github.com/a/b:443"])
def test_repository_url_rejects_credentials_and_invalid_destinations(url):
    with pytest.raises(RepositoryError): repository_url(url)


def test_llm_only_accepts_evidence_and_never_sends_keys_or_env_files(monkeypatch):
    from backend.sca_monitor.repository import llm
    line = 'subprocess.run(["pip", "install", "sample"])'
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            result = {"summary": "설치 호출 후보", "candidates": [{"file": "install.py", "line": 1, "evidence": line, "reason": "설치 호출", "dependency_file": "custom.list"}, {"file": "missing.py", "line": 1, "evidence": "invented", "reason": "bad", "dependency_file": ""}]}
            return json.dumps({"choices": [{"message": {"content": json.dumps(result)}}]}).encode()
    def request(req, timeout):
        body = json.loads(req.data)
        assert body["model"] == "deepseek/deepseek-v4.1-flash"
        assert "OPENROUTER_TEST_KEY" not in req.data.decode()
        assert "secret-env-value" not in req.data.decode()
        assert body["provider"]["data_collection"] == "deny"
        assert "tools" not in body
        return Response()
    monkeypatch.setattr(llm, "urlopen", request)
    result = llm.analyze_with_llm({"install.py": line, "custom.list": "sample==1.0", ".env": "SECRET=secret-env-value"}, "OPENROUTER_TEST_KEY")
    assert len(result["candidates"]) == 1
    assert result["rejected_evidence_count"] == 1


def test_private_dns_and_guest_response_limits(monkeypatch):
    from backend.sca_monitor.repository import transport, sandbox
    import socket, sys
    monkeypatch.setattr(transport.socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(RepositoryError): transport.public_addresses("public-looking.example")
    with pytest.raises(RepositoryError): sandbox.bounded_guest_read([sys.executable, "-c", "print('x'*10000)"], maximum=100)
