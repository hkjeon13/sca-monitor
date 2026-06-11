#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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


def run_postgres_smoke(database_url: str) -> dict[str, Any]:
    database = Database(database_url)
    database.migrate()
    return run_smoke(database)


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
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    container_name = None
    try:
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
        result = run_postgres_smoke(database_url)
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
    else:
        print(f"postgres smoke failed: {result.get('error')} {result.get('detail', '')}", file=sys.stderr)
    return 0 if result["status"] in {"ok", "skipped"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
