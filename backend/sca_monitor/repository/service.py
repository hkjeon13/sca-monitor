from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import PurePosixPath, Path

from ..db import utcnow, json_column
from .transport import repository_url, RepositoryError
from .vault import Vault
from .llm import MODEL

TERMINAL = {"completed", "partial", "failed", "cancelled"}


class Repositories:
    def __init__(self, workspace):
        self.workspace, self.app, self.db = workspace, workspace.app, workspace.db
        self.vault = Vault(self.app.settings.data_dir)

    def error(self, status, message):
        from ..workspace import ApiError
        raise ApiError(status, message)

    def capabilities(self):
        configured = bool(os.getenv("OPENROUTER_API_KEY"))
        with self.db.connect() as c:
            configured = configured or c.execute("SELECT id FROM repository_llm_settings WHERE id=1").fetchone() is not None
        sandbox = Path(os.getenv("SCA_SANDBOX_READY_FILE", str(self.app.settings.data_dir / "sandbox-ready.json")))
        try:
            ready = json.loads(sandbox.read_text())
            available = isinstance(ready, dict) and ready.get("isolation") == "kvm" and os.access("/dev/kvm", os.R_OK | os.W_OK) and Path(ready["base_image"]).is_file() and os.access(ready["launcher"], os.X_OK)
        except (OSError, ValueError, KeyError, TypeError): available = False
        return {"llm": {"provider": "OpenRouter", "model": MODEL, "configured": configured}, "deep_analysis": available, "deep_profiles": ["python", "node", "docker"], "deep_max_seconds": 900}

    def llm_key(self):
        if os.getenv("OPENROUTER_API_KEY"): return os.environ["OPENROUTER_API_KEY"]
        with self.db.connect() as c:
            row = c.execute("SELECT encrypted_key FROM repository_llm_settings WHERE id=1").fetchone()
        return self.vault.decrypt(row["encrypted_key"], "system:openrouter")["secret"] if row else None

    def settings(self, user, body=None):
        if not user["is_admin"]: self.error(403, "관리자만 LLM 연결을 설정할 수 있습니다.")
        if body is not None:
            secret = str(body.get("api_key") or "").strip()
            if not 20 <= len(secret) <= 4096 or any(ord(v) < 33 for v in secret): self.error(400, "OpenRouter API 키를 입력해 주세요.")
            encrypted, version = self.vault.encrypt({"secret": secret}, "system:openrouter")
            with self.db.connect() as c:
                c.execute("""INSERT INTO repository_llm_settings(id,encrypted_key,key_version,updated_by,updated_at) VALUES(1,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET encrypted_key=excluded.encrypted_key,key_version=excluded.key_version,updated_by=excluded.updated_by,updated_at=excluded.updated_at""", (encrypted, version, user["id"], utcnow()))
        return self.capabilities()

    def credential(self, user, pid, body, cid=None):
        self.workspace.require_project(user, pid, owner=True)
        if cid:
            with self.db.connect() as c:
                existing = c.execute("SELECT id,provider,host FROM repository_credentials WHERE id=? AND project_id=?", (cid, pid)).fetchone()
                if not existing: self.error(404, "자격 증명을 찾을 수 없습니다.")
        try:
            info = repository_url(body.get("repository_url", ""), body.get("provider"))
        except RepositoryError as error:
            self.error(400, str(error))
        if cid and (existing["provider"] != info["provider"] or existing["host"] != info["host"]): self.error(400, "교체할 자격 증명의 제공자·호스트를 변경할 수 없습니다. 새 자격 증명으로 등록해 주세요.")
        username, secret, label = str(body.get("username", "")).strip(), str(body.get("secret", "")).strip(), str(body.get("label", "")).strip()
        if not label or len(label) > 100 or not 1 <= len(secret) <= 4096 or len(username) > 200 or any(ord(v) < 32 for v in username + secret): self.error(400, "표시 이름과 올바른 사용자명·토큰을 입력해 주세요.")
        cid = cid or str(uuid.uuid4())
        encrypted, version = self.vault.encrypt({"username": username, "secret": secret}, pid + ":" + cid)
        now = utcnow()
        with self.db.connect() as c:
            c.execute("""INSERT INTO repository_credentials(id,project_id,label,provider,host,encrypted_value,key_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET label=excluded.label,provider=excluded.provider,host=excluded.host,encrypted_value=excluded.encrypted_value,key_version=excluded.key_version,updated_at=excluded.updated_at""", (cid, pid, label, info["provider"], info["host"], encrypted, version, now, now))
        return {"id": cid, "label": label, "configured": True}

    def secret(self, pid, cid):
        if not cid: return None
        with self.db.connect() as c:
            row = c.execute("SELECT encrypted_value FROM repository_credentials WHERE id=? AND project_id=?", (cid, pid)).fetchone()
        if not row: raise RepositoryError("저장소 자격 증명이 없습니다.")
        return self.vault.decrypt(row["encrypted_value"], pid + ":" + cid)

    def list(self, user, pid):
        self.workspace.require_project(user, pid)
        with self.db.connect() as c:
            repos = [dict(r) for r in c.execute("SELECT * FROM repository_connections WHERE project_id=? ORDER BY created_at DESC", (pid,)).fetchall()]
            credentials = [dict(r) for r in c.execute("SELECT id,label,provider,host,updated_at FROM repository_credentials WHERE project_id=? ORDER BY label", (pid,)).fetchall()]
            scans = [self.public_scan(r) for r in c.execute("SELECT * FROM repository_scan_runs WHERE project_id=? ORDER BY created_at DESC LIMIT 40", (pid,)).fetchall()]
        return {"items": repos, "credentials": credentials, "scans": scans, "capabilities": self.capabilities()}

    def create(self, user, pid, body):
        self.workspace.require_project(user, pid, write=True)
        try: info = repository_url(body.get("url", ""))
        except RepositoryError as error: self.error(400, str(error))
        ref, subpath = str(body.get("ref") or "HEAD").strip(), str(body.get("subpath") or "").strip().strip("/")
        if not ref or len(ref) > 200 or any(ord(v) < 32 for v in ref) or len(subpath) > 300 or ".." in PurePosixPath(subpath).parts or "\\" in subpath or "$" in subpath: self.error(400, "분석 ref 또는 하위 경로가 올바르지 않습니다.")
        cid = body.get("credential_id") or None
        with self.db.connect() as c:
            if cid and not c.execute("SELECT id FROM repository_credentials WHERE id=? AND project_id=? AND provider=? AND host=?", (cid, pid, info["provider"], info["host"])).fetchone(): self.error(400, "이 프로젝트·제공자에서 사용할 수 없는 자격 증명입니다.")
            if c.execute("SELECT id FROM repository_connections WHERE project_id=? AND url=? AND ref=? AND subpath=?", (pid, info["url"], ref, subpath)).fetchone(): self.error(409, "동일한 저장소·ref·경로가 이미 등록되어 있습니다.")
        target = self.workspace.create_target(user, pid, {"name": str(body.get("name") or info["namespace"])[:100], "environment": body.get("environment", "dev"), "collection_mode": "push", "metadata": {"inventory_basis": "repository_report", "deployment_verified": False}})
        rid, now = str(uuid.uuid4()), utcnow()
        with self.db.connect() as c:
            c.execute("INSERT INTO repository_connections(id,project_id,provider,host,namespace,url,ref,subpath,credential_id,target_id,created_at,updated_at,llm_enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (rid, pid, info["provider"], info["host"], info["namespace"], info["url"], ref, subpath, cid, target["id"], now, now, int(body.get("llm_enabled") is True)))
        scan = self.enqueue(user, pid, rid, str(body.get("idempotency_key") or uuid.uuid4()))
        return {"id": rid, "scan": scan, "target_id": target["id"]}

    def enqueue(self, user, pid, rid, key, parent_id=None, profile=None, run_command="", manifest=""):
        self.workspace.require_project(user, pid, write=True)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", key): self.error(400, "올바른 idempotency_key가 필요합니다.")
        with self.db.connect() as c:
            repo = c.execute("SELECT * FROM repository_connections WHERE project_id=? AND id=?", (pid, rid)).fetchone()
            if not repo: self.error(404, "저장소를 찾을 수 없습니다.")
            snapshot = dict(repo)
            if parent_id:
                parent = c.execute("SELECT * FROM repository_scan_runs WHERE id=? AND project_id=? AND repository_id=?", (parent_id, pid, rid)).fetchone()
                if not parent or parent["mode"] != "preliminary" or parent["status"] not in ("completed", "partial") or not parent["report"] or not parent["commit_sha"]: self.error(409, "완료된 1차 리포트가 필요합니다.")
                if profile not in ("python", "node", "docker"): self.error(400, "심층 분석 프로파일을 선택해 주세요.")
                if not isinstance(run_command, str) or len(run_command) > 2000 or "\x00" in run_command: self.error(400, "실행 명령은 2000자 이하 문자열이어야 합니다.")
                if manifest and manifest not in json_column(parent["report"], {}).get("dependency_files", []): self.error(400, "1차 리포트에서 확인한 설치 입력 파일을 선택해 주세요.")
                if not self.capabilities()["deep_analysis"]: self.error(503, "격리 분석 워커가 아직 준비되지 않았습니다.")
                snapshot = json_column(parent["snapshot"], {}) | {"profile": profile, "run_command": run_command, "manifest": manifest, "commit_sha": parent["commit_sha"], "archive_sha256": parent["archive_sha256"]}
            existing = c.execute("SELECT * FROM repository_scan_runs WHERE project_id=? AND idempotency_key=?", (pid, key)).fetchone()
            if existing:
                if existing["repository_id"] != rid or existing["parent_id"] != parent_id: self.error(409, "다른 요청에 사용한 키입니다.")
                return self.public_scan(existing)
            count = c.execute("SELECT COUNT(*) AS c FROM repository_scan_runs WHERE project_id=? AND status NOT IN ('completed','partial','failed','cancelled')", (pid,)).fetchone()["c"]
            if count >= 3: self.error(429, "프로젝트의 분석 작업 3개가 진행 중입니다.")
            sid = str(uuid.uuid4())
            c.execute("INSERT INTO repository_scan_runs(id,project_id,repository_id,mode,parent_id,requested_by,idempotency_key,status,phase,snapshot,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (sid, pid, rid, "deep" if parent_id else "preliminary", parent_id, user["id"], key, "queued", "queued", json.dumps(snapshot), utcnow()))
            row = c.execute("SELECT * FROM repository_scan_runs WHERE id=?", (sid,)).fetchone()
        return self.public_scan(row)

    def get_scan(self, user, pid, sid):
        self.workspace.require_project(user, pid)
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM repository_scan_runs WHERE id=? AND project_id=?", (sid, pid)).fetchone()
        if not row: self.error(404, "분석 작업을 찾을 수 없습니다.")
        return row

    @staticmethod
    def public_scan(row):
        value = dict(row)
        value.pop("snapshot", None)
        value["has_report"] = bool(value.pop("report", None))
        return value

    def report(self, user, pid, sid):
        row = self.get_scan(user, pid, sid)
        return {"scan": self.public_scan(row), "report": json_column(row["report"], None), "capabilities": self.capabilities()}

    def cancel(self, user, pid, sid):
        self.workspace.require_project(user, pid, write=True)
        row = self.get_scan(user, pid, sid)
        if row["status"] not in TERMINAL:
            with self.db.connect() as c:
                c.execute("UPDATE repository_scan_runs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,phase=CASE WHEN status='queued' THEN 'cancelled' ELSE phase END WHERE id=? AND status NOT IN ('completed','partial','failed','cancelled')", (sid,))
        return self.public_scan(self.get_scan(user, pid, sid))

    def components(self, user, pid, sid, query):
        self.get_scan(user, pid, sid)
        cursor, parent = query.get("cursor", [""])[0], query.get("parent", [""])[0]
        if cursor and not re.fullmatch(r"[0-9a-f-]{36}", cursor): self.error(400, "잘못된 목록 커서입니다.")
        params, where = [sid, cursor], ["c.scan_id=?", "c.id>?"]
        if parent:
            where.append("EXISTS(SELECT 1 FROM repository_edges e WHERE e.scan_id=c.scan_id AND e.child_id=c.id AND e.parent_id=?)"); params.append(parent)
        elif not query.get("all"):
            where.append("(c.relationship='direct' OR NOT EXISTS(SELECT 1 FROM repository_edges e WHERE e.scan_id=c.scan_id AND e.child_id=c.id))")
        with self.db.connect() as c:
            rows = c.execute("SELECT c.*,(SELECT COUNT(*) FROM repository_edges e WHERE e.scan_id=c.scan_id AND e.parent_id=c.id) AS child_count FROM repository_components c WHERE " + " AND ".join(where) + " ORDER BY c.id LIMIT 101", params).fetchall()
        items = [dict(r) | {"evidence": json_column(r["evidence"], [])} for r in rows[:100]]
        return {"items": items, "next_cursor": items[-1]["id"] if len(rows) > 100 else None}

    def route(self, request, method, parts, body, query, user):
        if parts == ["admin", "repository-analysis", "settings"] and method in ("GET", "POST"):
            return self.workspace.reply(request, self.settings(user, body if method == "POST" else None))
        if len(parts) < 3 or parts[0] != "projects": return False
        pid, area = parts[1:3]
        if area == "repositories":
            if len(parts) == 3 and method == "GET": return self.workspace.reply(request, self.list(user, pid))
            if len(parts) == 3 and method == "POST": return self.workspace.reply(request, self.create(user, pid, body), 201)
            if len(parts) == 5 and parts[4] == "scans" and method == "POST": return self.workspace.reply(request, self.enqueue(user, pid, parts[3], str(body.get("idempotency_key", ""))), 202)
        if area == "repository-credentials" and method in ("POST", "PATCH") and len(parts) in (3, 4):
            return self.workspace.reply(request, self.credential(user, pid, body, parts[3] if len(parts) == 4 else None), 201 if method == "POST" else 200)
        if area == "repository-scans" and len(parts) >= 4:
            sid = parts[3]
            if len(parts) == 4 and method == "GET": return self.workspace.reply(request, self.public_scan(self.get_scan(user, pid, sid)))
            if len(parts) == 5:
                action = parts[4]
                if action == "report" and method == "GET": return self.workspace.reply(request, self.report(user, pid, sid))
                if action == "components" and method == "GET": return self.workspace.reply(request, self.components(user, pid, sid, query))
                if action == "cancel" and method == "POST": return self.workspace.reply(request, self.cancel(user, pid, sid))
                if action == "deep-analysis" and method == "POST":
                    row = self.get_scan(user, pid, sid)
                    return self.workspace.reply(request, self.enqueue(user, pid, row["repository_id"], str(body.get("idempotency_key", "")), sid, body.get("profile"), body.get("run_command", ""), body.get("manifest", "")), 202)
        return False
