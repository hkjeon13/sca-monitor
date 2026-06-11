#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import Settings
from backend.sca_monitor.db import Database
from scripts.db_smoke import run_smoke


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_tcp(host: str, port: int, timeout_seconds: int) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def run_command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=True, text=True)


def docker_database_url(port: int, user: str, password: str, database: str) -> str:
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{database}"


def start_postgres_container(args: argparse.Namespace) -> tuple[str, str]:
    if not shutil.which("docker"):
        raise RuntimeError("docker executable not found")
    port = args.port or find_free_port()
    container_name = args.container_name or f"sca-monitor-pg-smoke-{uuid.uuid4().hex[:12]}"
    run_command(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "--rm",
            "-e",
            f"POSTGRES_USER={args.user}",
            "-e",
            f"POSTGRES_PASSWORD={args.password}",
            "-e",
            f"POSTGRES_DB={args.database}",
            "-p",
            f"127.0.0.1:{port}:5432",
            args.image,
        ]
    )
    if not wait_for_tcp("127.0.0.1", port, args.timeout_seconds):
        raise RuntimeError(f"PostgreSQL container did not accept TCP connections within {args.timeout_seconds}s")
    return container_name, docker_database_url(port, args.user, args.password, args.database)


def stop_container(container_name: str) -> None:
    run_command(["docker", "rm", "-f", container_name], check=False)


def run_postgres_smoke(database_url: str, *, migrate: bool = True, write_check: bool = True) -> dict[str, Any]:
    database = Database(database_url)
    if migrate:
        database.migrate()
    return run_smoke(database, write_check=write_check)


def is_postgres_url(value: str | None) -> bool:
    return bool(value and value.startswith(("postgres://", "postgresql://")))


def run_production_preflight(env: dict[str, str]) -> dict[str, Any]:
    urls = {
        "migration": env.get("MIGRATION_DATABASE_URL", ""),
        "api": env.get("API_DATABASE_URL", ""),
        "worker": env.get("WORKER_DATABASE_URL", ""),
    }
    result: dict[str, Any] = {"status": "ok", "checks": {}}
    for role, url in urls.items():
        if not url:
            result["checks"][role] = {"status": "failed", "error": f"{role.upper()}_DATABASE_URL is not configured"}
            continue
        if not is_postgres_url(url):
            result["checks"][role] = {"status": "failed", "error": f"{role.upper()}_DATABASE_URL is not PostgreSQL"}
            continue
        try:
            if role == "migration":
                result["checks"][role] = run_postgres_smoke(url, migrate=True, write_check=True)
            else:
                result["checks"][role] = run_postgres_smoke(url, migrate=False, write_check=False)
        except Exception as exc:  # noqa: BLE001 - preflight output should keep checking other roles.
            result["checks"][role] = {"status": "failed", "error": exc.__class__.__name__, "detail": str(exc)}
    if any(check.get("status") != "ok" for check in result["checks"].values()):
        result["status"] = "failed"
    return result


def run_api_workflow_smoke(database_url: str) -> dict[str, Any]:
    app = ScaMonitorApp(
        Settings(
            app_env="postgres-smoke",
            host="127.0.0.1",
            port=0,
            data_dir=REPO_ROOT / ".data",
            database_url=database_url,
            database_path=REPO_ROOT / ".data" / "postgres-smoke.sqlite3",
            frontend_dir=REPO_ROOT / "frontend",
            smoke_token="postgres-smoke",
        )
    )
    service_id = f"pg-smoke-{uuid.uuid4().hex[:12]}"
    before = app.overview()
    service = app.create_service(
        {
            "service_id": service_id,
            "environment": "prod",
            "owner_team": "platform",
            "collection_mode": "push",
        }
    )
    snapshot = app.push_snapshot(
        {
            "service_id": service_id,
            "environment": "prod",
            "snapshot_id": "postgres-smoke",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    after = app.overview()
    if after["service_count"] < before["service_count"] + 1:
        raise RuntimeError("API workflow smoke did not increase service_count")
    if snapshot["idempotency_status"] != "created":
        raise RuntimeError("API workflow smoke snapshot was not created")
    return {
        "service_id": service["service"]["service_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "service_count_before": before["service_count"],
        "service_count_after": after["service_count"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run PostgreSQL migration and DB smoke against a real PostgreSQL database.")
    parser.add_argument("--database-url", help="Existing PostgreSQL database URL.")
    parser.add_argument("--use-docker", action="store_true", help="Start a temporary PostgreSQL container when --database-url is not provided.")
    parser.add_argument("--image", default="postgres:16", help="Docker image for --use-docker.")
    parser.add_argument("--container-name", help="Optional Docker container name.")
    parser.add_argument("--port", type=int, help="Optional host port for Docker PostgreSQL.")
    parser.add_argument("--user", default="sca_monitor")
    parser.add_argument("--password", default="sca_monitor")
    parser.add_argument("--database", default="sca_monitor")
    parser.add_argument("--timeout-seconds", type=int, default=45)
    parser.add_argument("--keep-container", action="store_true")
    parser.add_argument("--with-api-workflow", action="store_true", help="Run a service registration and snapshot push workflow through ScaMonitorApp.")
    parser.add_argument("--skip-migrate", action="store_true", help="Do not run migrations before DB smoke.")
    parser.add_argument("--read-only", action="store_true", help="Skip transactional write/rollback check.")
    parser.add_argument(
        "--production-preflight",
        action="store_true",
        help="Validate MIGRATION/API/WORKER PostgreSQL URLs as a split-credential production cutover preflight.",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    container_name = None
    try:
        if args.production_preflight:
            result = run_production_preflight(os.environ)
            container_name = None
            database_url = None
        else:
            database_url = args.database_url
            if not database_url:
                if not args.use_docker:
                    result = {
                        "status": "skipped",
                        "reason": "provide --database-url or --use-docker to run PostgreSQL integration smoke",
                    }
                    print(json.dumps(result, indent=2) if args.json else result["reason"])
                    return 0
                container_name, database_url = start_postgres_container(args)
            result = run_postgres_smoke(database_url, migrate=not args.skip_migrate, write_check=not args.read_only)
            if result["status"] == "ok" and args.with_api_workflow:
                result["api_workflow"] = run_api_workflow_smoke(database_url)
            result["database_url_source"] = "docker" if container_name else "provided"
    except Exception as exc:  # noqa: BLE001 - smoke output should expose exact integration blocker.
        result = {"status": "failed", "error": exc.__class__.__name__, "detail": str(exc)}
    finally:
        if container_name and not args.keep_container:
            stop_container(container_name)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ok":
        migration = result["migration"]
        print(f"postgres smoke ok: migration={migration['current']}/{migration['required']}")
    elif result["status"] == "skipped":
        print(f"postgres smoke skipped: {result['reason']}")
    elif args.production_preflight:
        print("postgres production preflight failed", file=sys.stderr)
    else:
        print(f"postgres smoke failed: {result.get('error')} {result.get('detail', '')}", file=sys.stderr)
    return 0 if result["status"] in {"ok", "skipped"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
