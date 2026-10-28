"""One bounded repository job at a time; source files never execute in this worker."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..coordination import interactive_write
from ..db import canonical_package_name, json_column, utcnow
from ..versioning import version_is_affected
from .scanner import Analyzer, archive_files, redact
from .transport import fetch_repository, resolve_dockerhub_image, RepositoryError
from .llm import analyze_with_llm
from .service import TERMINAL


class Cancelled(Exception):
    pass


class RepositoryWorker:
    def __init__(self, app, fetcher=fetch_repository, llm=analyze_with_llm, sandbox=None):
        self.app, self.db, self.service = app, app.db, app.workspace.repositories
        self.fetcher, self.llm, self.sandbox = fetcher, llm, sandbox
        self.root = app.settings.data_dir / "repository-jobs"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def check(self, sid, phase=None):
        with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
            row = c.execute("SELECT cancel_requested FROM repository_scan_runs WHERE id=?", (sid,)).fetchone()
            if not row or row["cancel_requested"]: raise Cancelled()
            c.execute("UPDATE repository_scan_runs SET heartbeat_at=?,phase=COALESCE(?,phase) WHERE id=?", (utcnow(), phase, sid))

    def claim(self):
        with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=35)).isoformat()
            c.execute("UPDATE repository_scan_runs SET status='failed',phase='failed',error=?,finished_at=? WHERE status='running' AND heartbeat_at<?", ("분석 워커가 중단되었습니다. 이전 리포트는 보존됩니다. 새 분석을 요청해 주세요.", utcnow(), cutoff))
            row = c.execute("SELECT * FROM repository_scan_runs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if not row: return None
            now = utcnow()
            changed = c.execute("UPDATE repository_scan_runs SET status='running',phase='preparing',started_at=?,heartbeat_at=? WHERE id=? AND status='queued'", (now, now, row["id"])).rowcount
            if changed == 1:
                c.execute("UPDATE repository_connections SET last_checked_at=? WHERE id=?", (now, row["repository_id"]))
            return dict(row) if changed == 1 else None

    def schedule_due(self):
        """Periodic refresh can only enqueue preliminary jobs, never execution."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
            repo = c.execute("""SELECT r.* FROM repository_connections r JOIN projects p ON p.id=r.project_id
                WHERE p.status='active' AND (r.last_checked_at IS NULL OR r.last_checked_at<?)
                AND NOT EXISTS(SELECT 1 FROM repository_scan_runs s WHERE s.repository_id=r.id AND s.status IN ('queued','running'))
                ORDER BY r.created_at LIMIT 1""", (cutoff,)).fetchone()
            if not repo: return
            owner = c.execute("SELECT u.* FROM workspace_users u JOIN project_memberships m ON m.user_id=u.id WHERE m.project_id=? AND m.role='owner' AND u.disabled=0 ORDER BY u.id LIMIT 1", (repo["project_id"],)).fetchone()
            c.execute("UPDATE repository_connections SET last_checked_at=? WHERE id=?", (utcnow(), repo["id"]))
        if owner:
            self.service.enqueue(dict(owner), repo["project_id"], repo["id"], "scheduled_" + uuid.uuid4().hex)

    def run_once(self):
        job = self.claim()
        if not job:
            self.schedule_due()
            return None
        sid = job["id"]
        try:
            self.check(sid, "fetching")
            snapshot = json_column(job["snapshot"], {})
            directory = self.root / sid
            directory.mkdir(mode=0o700, exist_ok=True)
            archive = directory / "source.tar.gz"
            if job["mode"] == "deep":
                with self.db.connect() as c:
                    parent = c.execute("SELECT * FROM repository_scan_runs WHERE id=? AND project_id=?", (job["parent_id"], job["project_id"])).fetchone()
                content = (self.root / parent["id"] / "source.tar.gz").read_bytes()
                if hashlib.sha256(content).hexdigest() != parent["archive_sha256"]:
                    raise RepositoryError("원본 리포트의 저장소 보관본을 검증하지 못했습니다.")
                sha = parent["commit_sha"]
            else:
                secret = self.service.secret(job["project_id"], snapshot.get("credential_id"))
                sha, content = self.fetcher(snapshot, secret)
            self.check(sid, "analyzing")
            with archive.open("xb") as target: target.write(content)
            archive.chmod(0o600)
            archive_hash = hashlib.sha256(content).hexdigest()
            with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
                c.execute("UPDATE repository_scan_runs SET commit_sha=?,archive_sha256=? WHERE id=?", (sha, archive_hash, sid))
            files, initial_gaps = archive_files(content, snapshot.get("subpath", ""))
            analyzer = Analyzer(sid, files)
            result = analyzer.run()
            result["llm"] = {"status": "not_requested" if job["mode"] == "deep" else "disabled", "candidates": []}
            result["gaps"] = initial_gaps + result["gaps"]
            if job["mode"] == "preliminary" and self.fetcher is fetch_repository:
                for image in result["images"][:10]:
                    self.check(sid)
                    if image.get("requested_platform") != "linux/amd64":
                        result["gaps"].append({"file": image["file"], "reason": "unsupported_image_platform"})
                        continue
                    try: image.update(resolve_dockerhub_image(image["reference"]))
                    except Exception: result["gaps"].append({"file": image["file"], "reason": "base_image_digest_unresolved"})
            if job["mode"] == "preliminary" and snapshot.get("llm_enabled"):
                key = self.service.llm_key()
                self.check(sid, "llm_analysis")
                result["llm"] = self.llm(files, key) if key else {"status": "not_configured", "candidates": []}
                for candidate in result["llm"].get("candidates", []):
                    if candidate.get("dependency_file"):
                        analyzer.requirements(candidate["dependency_file"])
                analyzer.reconcile()
                result["components"], result["edges"] = list(analyzer.components.values()), sorted(analyzer.edges)
                result["dependency_files"] = sorted(set(analyzer.documents))
                result["gaps"] += [g for g in analyzer.gaps if g not in result["gaps"]]
                if analyzer.documents: result["gaps"] = [g for g in result["gaps"] if g["reason"] != "no_supported_dependency_manifest"]
                result["installation_candidates"] += result["llm"].get("candidates", [])
                if result["llm"]["status"] != "completed": result["gaps"].append({"reason": "llm_analysis_unavailable"})
                if result["llm"].get("limited"): result["gaps"].append({"reason": "llm_input_scope_limited"})
            if job["mode"] == "deep":
                snapshot["dependency_files"] = json_column(parent["report"], {}).get("dependency_files", [])
                snapshot["image_pins"] = json_column(parent["report"], {}).get("images", [])
                self.check(sid, "sandbox_preparing")
                if self.sandbox is None:
                    from .sandbox import run_sandbox
                    self.sandbox = run_sandbox
                deep = self.sandbox(job, snapshot, archive, lambda phase=None: self.check(sid, phase))
                result["runtime"] = deep
                for index, sbom in enumerate(deep.get("sboms", [])):
                    analyzer.sbom(f"sandbox/{index}/sbom.json", sbom["document"], origin=sbom["origin"], module=snapshot.get("subpath", ""))
                result["runtime"] = {k: v for k, v in deep.items() if k != "sboms"} | {"sbom_count": len(deep.get("sboms", []))}
                analyzer.reconcile()
                result["components"], result["edges"] = list(analyzer.components.values()), sorted(analyzer.edges)
                result["gaps"] += deep.get("gaps", [])
                if not deep.get("completed"): result["gaps"].append({"reason": "sandbox_execution_partial"})
                result["comparison"] = self.compare(parent, result)
            self.check(sid, "matching")
            findings = self.match(result["components"], sid)
            if job["mode"] == "deep":
                original = json_column(parent["report"], {})
                previous = {(f["package"], f["version"], f["advisory_id"]) for f in original.get("findings", [])}
                result["comparison"]["new_finding_count"] = sum((f["package"], f["version"], f["advisory_id"]) not in previous for f in findings) if original.get("finding_count", 0) <= len(previous) else None
            self.check(sid, "reporting")
            components, edges = result.pop("components"), result.pop("edges")
            identities = {(c["ecosystem"], c["name"], c["version"]) for c in components}
            exact = {c for c in identities if c[2]}
            result.update({"mode": job["mode"], "commit_sha": sha, "archive_sha256": archive_hash, "created_at": utcnow(), "execution_performed": bool(result.get("runtime", {}).get("project_execution_performed")), "coverage_note": "저장소·분석 환경의 관찰 결과이며 운영 배포 환경 전체를 보증하지 않습니다.", "component_count": len(identities), "graph_node_count": len(components), "exact_version_count": len(exact), "unresolved_version_count": len(identities) - len(exact), "edge_count": len(edges), "findings": findings[:500], "finding_count": len(findings), "graph_complete": False})
            observed_images = {item.get("reference") for item in result.get("runtime", {}).get("scanned_images", []) if item.get("origin") == "base_image"}
            for image in result["images"]:
                if image.get("resolved", image["reference"]) in observed_images: image["status"] = "sbom_observed"
                else: result["gaps"].append({"file": image["file"], "reason": "image_contents_require_artifact_analysis"})
            unknown_names = {c["name"] for c in components if not c["version"]}
            result["gaps"] = [g for g in result["gaps"] if not g["reason"].startswith("dependency_version_unresolved:") or g["reason"].split(":", 1)[1] in unknown_names]
            if components and not edges: result["gaps"].append({"reason": "transitive_dependency_graph_incomplete"})
            if job["mode"] == "deep":
                previous_gaps = {(g.get("file", ""), g["reason"]) for g in json_column(parent["report"], {}).get("gaps", [])}
                current_gaps = {(g.get("file", ""), g["reason"]) for g in result["gaps"]}
                result["comparison"]["resolved_gap_count"] = len(previous_gaps - current_gaps)
                result["comparison"]["remaining_gap_count"] = len(current_gaps)
            with interactive_write(self.app.settings.data_dir):
                result["source_coverage"] = self.app.workspace.sources()
            self.persist(job, result, components, edges)
            try:
                self.inventory(job, snapshot, components)
            except Exception:
                with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
                    c.execute("UPDATE repository_scan_runs SET error=? WHERE id=?", ("리포트는 저장했지만 모니터링 인벤토리 연결이 완료되지 않았습니다. 이전 인벤토리는 보존됩니다.", sid))
            return {"id": sid, "status": "partial" if result["gaps"] else "completed"}
        except Cancelled:
            self.finish_error(sid, "cancelled", "사용자가 분석을 취소했습니다. 기존 리포트·인벤토리는 보존됩니다.")
        except Exception as error:
            message = str(error) if isinstance(error, RepositoryError) else "분석을 완료하지 못했습니다. 저장소 접근·격리 워커 상태를 확인해 주세요."
            self.finish_error(sid, "failed", redact(message)[:1000])
        return {"id": sid, "status": "stopped"}

    def finish_error(self, sid, status, error):
        partial_report = None
        path = self.root / sid / "sandbox-partial.json"
        if path.is_file():
            try:
                evidence = json.loads(path.read_text())
                evidence["sbom_count"] = len(evidence.pop("sboms", []))
                partial_report = {"mode": "deep", "coverage_note": "중단 시점까지 확보한 실행 증거입니다. 패키지·취약점 집계와 인벤토리 갱신은 완료되지 않았으며 기존 리포트는 보존됩니다.", "execution_performed": bool(evidence.get("project_execution_performed")), "runtime": evidence, "gaps": [{"reason": "sandbox_execution_partial"}], "findings": []}
            except (OSError, ValueError, TypeError, AttributeError):
                pass
        with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
            row = c.execute("SELECT commit_sha FROM repository_scan_runs WHERE id=?", (sid,)).fetchone()
            if partial_report: partial_report["commit_sha"] = row["commit_sha"]
            c.execute("UPDATE repository_scan_runs SET status=?,phase=?,error=?,finished_at=?,report=COALESCE(report,?) WHERE id=? AND report IS NULL", (status, status, error, utcnow(), json.dumps(partial_report) if partial_report else None, sid))

    def match(self, components, sid):
        findings, seen = [], {}
        for start in range(0, len(components), 50):
            self.check(sid)
            with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
                for component in components[start:start + 50]:
                    if not component["version"]: continue
                    rows = c.execute("SELECT id,advisory_id,source,severity,summary,affected_versions,affected_ranges,fixed_version FROM advisories WHERE ecosystem=? AND canonical_package_name=?", (component["ecosystem"], canonical_package_name(component["ecosystem"], component["name"]))).fetchall()
                    for row in rows:
                        identity = (component["ecosystem"], component["name"], component["version"], row["id"])
                        if identity in seen:
                            seen[identity]["component_ids"].append(component["id"]); continue
                        if not version_is_affected(component["version"], json_column(row["affected_versions"], []), json_column(row["affected_ranges"], [])): continue
                        finding = {"component_id": component["id"], "component_ids": [component["id"]], "package": component["name"], "version": component["version"], "advisory_id": row["advisory_id"], "advisory_pk": row["id"], "source": row["source"], "severity": row["severity"], "summary": row["summary"], "fixed_version": row["fixed_version"]}
                        seen[identity] = finding; findings.append(finding)
        return findings

    def persist(self, job, report, components, edges):
        self.check(job["id"])
        # The entire immutable report and its graph become visible together.
        with interactive_write(self.app.settings.data_dir), self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT cancel_requested,report FROM repository_scan_runs WHERE id=?", (job["id"],)).fetchone()
            if row["cancel_requested"]: raise Cancelled()
            if row["report"]: raise RepositoryError("이미 완료된 리포트입니다.")
            for item in components:
                c.execute("INSERT INTO repository_components(id,scan_id,ecosystem,name,version,declared_range,module,origin,relationship,evidence,purl) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (item["id"], job["id"], item["ecosystem"], item["name"], item["version"], item["declared_range"], item["module"], item["origin"], item["relationship"], json.dumps(item["evidence"]), item["purl"]))
            for a, b in edges:
                c.execute("INSERT INTO repository_edges(scan_id,parent_id,child_id) VALUES(?,?,?) ON CONFLICT DO NOTHING", (job["id"], a, b))
            status = "partial" if report["gaps"] else "completed"
            c.execute("UPDATE repository_scan_runs SET report=?,status=?,phase=?,finished_at=? WHERE id=?", (json.dumps(report, ensure_ascii=False), status, status, utcnow(), job["id"]))
            c.execute("UPDATE repository_connections SET last_commit=?,last_checked_at=? WHERE id=?", (report["commit_sha"], utcnow(), job["repository_id"]))

    def inventory(self, job, snapshot, components):
        dependencies = {(x["ecosystem"], x["name"], x["version"]): {"ecosystem": x["ecosystem"], "name": x["name"], "version": x["version"], "direct": x["relationship"] == "direct", "source": "repository:" + job["id"]} for x in components if x["version"]}
        if not dependencies: return
        with interactive_write(self.app.settings.data_dir):
            with self.db.connect() as c:
                target = c.execute("SELECT s.* FROM project_targets pt JOIN services s ON s.id=pt.service_pk WHERE pt.id=? AND pt.project_id=?", (snapshot["target_id"], job["project_id"])).fetchone()
                if not target: return
                old = c.execute("SELECT d.* FROM dependencies d JOIN dependency_snapshots ds ON ds.id=d.snapshot_pk WHERE ds.service_pk=? AND ds.is_latest", (target["id"],)).fetchall()
            # Repository observations are not a complete deployed environment.
            # Preserve prior versions/entries rather than auto-resolving impacts.
            for dep in old:
                key = (dep["ecosystem"], dep["package_name"], dep["resolved_version"])
                dependencies.setdefault(key, {"ecosystem": key[0], "name": key[1], "version": key[2], "direct": bool(dep["direct_dependency"]), "source": "retained:partial-repository-inventory"})
            if len(dependencies) > 10000:
                raise RepositoryError("인벤토리 한도를 초과했습니다. 기존 스냅샷은 보존합니다.")
            self.app.push_snapshot({"service_id": target["service_id"], "environment": target["environment"], "snapshot_id": "repository-" + job["id"], "source": {"type": "repository"}, "dependencies": list(dependencies.values())})

    def compare(self, parent, result):
        with self.db.connect() as c:
            old = {(r["ecosystem"], r["name"], r["version"]) for r in c.execute("SELECT ecosystem,name,version FROM repository_components WHERE scan_id=?", (parent["id"],)).fetchall()}
        added = list({(c["ecosystem"], c["name"], c["version"]): c for c in result["components"] if (c["ecosystem"], c["name"], c["version"]) not in old}.values())
        return {"parent_id": parent["id"], "added_component_count": len(added), "added_components": [{k: item[k] for k in ("name", "version", "origin")} for item in added[:200]], "original_report_preserved": True}
