#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.deployment_input_readiness import parse_env_file, readiness
from scripts.postgres_integration_smoke import run_production_preflight
from scripts.validate_database_env_file import validate
from scripts.verify_backup_restore import verify_backup_restore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a sanitized PostgreSQL cutover readiness report.")
    parser.add_argument("--env-file", help="Runtime .env file to assess.")
    parser.add_argument("--database-env-file", help="Protected PostgreSQL split credential env file to validate.")
    parser.add_argument("--backup-path", help="SQLite backup file to restore-check before cutover.")
    parser.add_argument("--require-postgres", action="store_true", help="Require PostgreSQL-ready inputs.")
    parser.add_argument("--require-split", action="store_true", help="Require split migration/API/worker credentials.")
    parser.add_argument("--require-runtime-inputs", action="store_true", help="Require production runtime inputs.")
    parser.add_argument(
        "--run-production-preflight",
        action="store_true",
        help="Run live PostgreSQL production preflight against configured split credentials.",
    )
    parser.add_argument("--output", help="Optional path to write the sanitized JSON report with mode 0600.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def status_weight(status: str) -> int:
    if status in {"blocked", "failed"}:
        return 2
    if status == "action_required":
        return 1
    return 0


def rollup_status(items: list[dict[str, Any]]) -> str:
    weights = [status_weight(str(item.get("status", "skipped"))) for item in items]
    if any(weight == 2 for weight in weights):
        return "blocked"
    if any(weight == 1 for weight in weights):
        return "action_required"
    return "ok"


def report(
    *,
    env_file: Path | None,
    database_env_file: Path | None,
    backup_path: Path | None,
    require_postgres: bool,
    require_split: bool,
    require_runtime_inputs: bool,
    run_live_preflight: bool,
) -> dict[str, Any]:
    env = parse_env_file(str(env_file)) if env_file else {}
    if env_file:
        env["_SCA_MONITOR_ENV_FILE_LOADED"] = "1"
    database_env: dict[str, Any] = {"status": "skipped", "database_env_file": "not_configured"}
    if database_env_file:
        database_env = validate(database_env_file)
        env.update(parse_env_file(str(database_env_file)))

    deployment_inputs = readiness(
        env,
        require_postgres=require_postgres,
        require_split=require_split,
        require_runtime_inputs=require_runtime_inputs,
    )
    backup_restore = (
        verify_backup_restore(backup_path)
        if backup_path
        else {"status": "skipped", "backup_path": "not_configured", "restore_copy_path": None}
    )
    production_preflight = (
        run_production_preflight(env)
        if run_live_preflight
        else {"status": "skipped", "reason": "live PostgreSQL preflight not requested"}
    )
    items = [deployment_inputs, database_env, backup_restore, production_preflight]
    status = rollup_status(items)
    return {
        "status": status,
        "summary": {
            "ok": len([item for item in items if item.get("status") in {"ok", "ready"}]),
            "action_required": len([item for item in items if item.get("status") == "action_required"]),
            "skipped": len([item for item in items if item.get("status") == "skipped"]),
            "blockers": len([item for item in items if item.get("status") in {"blocked", "failed"}]),
        },
        "inputs": {
            "env_file": "configured" if env_file else "not_configured",
            "database_env_file": "configured" if database_env_file else "not_configured",
            "backup_path": "configured" if backup_path else "not_configured",
            "production_preflight": "enabled" if run_live_preflight else "skipped",
        },
        "deployment_inputs": deployment_inputs,
        "database_env": database_env,
        "backup_restore": backup_restore,
        "production_preflight": production_preflight,
    }


def write_report(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
    finally:
        try:
            os.chmod(path, 0o600)
        except FileNotFoundError:
            pass


def main() -> int:
    args = parse_args()
    result = report(
        env_file=Path(args.env_file) if args.env_file else None,
        database_env_file=Path(args.database_env_file) if args.database_env_file else None,
        backup_path=Path(args.backup_path) if args.backup_path else None,
        require_postgres=args.require_postgres,
        require_split=args.require_split,
        require_runtime_inputs=args.require_runtime_inputs,
        run_live_preflight=args.run_production_preflight,
    )
    if args.output:
        write_report(Path(args.output), result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"cutover readiness report: {result['status']}")
        print(
            "- summary: "
            f"ok={result['summary']['ok']} "
            f"action_required={result['summary']['action_required']} "
            f"blockers={result['summary']['blockers']}"
        )
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
