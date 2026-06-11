#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.configure_runtime_inputs import configure
from scripts.deployment_input_readiness import parse_env_file, readiness
from scripts.validate_database_env_file import validate


SYNTHETIC_DATABASE_ENV = "\n".join(
    [
        "MIGRATION_DATABASE_URL=postgresql://migration:synthetic-secret@postgres.invalid:5432/sca_monitor",
        "API_DATABASE_URL=postgresql://api:synthetic-secret@postgres.invalid:5432/sca_monitor",
        "WORKER_DATABASE_URL=postgresql://worker:synthetic-secret@postgres.invalid:5432/sca_monitor",
        "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required",
        "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true",
        "SCA_MONITOR_AUTO_MIGRATE=false",
        "SCA_MONITOR_API_AUTO_MIGRATE=false",
        "SCA_MONITOR_WORKER_AUTO_MIGRATE=false",
    ]
) + "\n"

BASE_RUNTIME_ENV = "\n".join(
    [
        "APP_ENV=prod",
        "SCA_MONITOR_PORT=18780",
        "SCA_MONITOR_SYSTEMD_MODE=validate",
        "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
        "SMOKE_TEST_TOKEN=synthetic-smoke-token",
    ]
) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run the PostgreSQL database env deploy gate without printing database URL values."
    )
    parser.add_argument(
        "--database-env-file",
        help="Optional PostgreSQL .env-style file to validate; omitted uses a synthetic split credential file.",
    )
    parser.add_argument(
        "--expect-status",
        choices=("ok", "action_required", "blocked"),
        help="Treat the command as successful only when the dry-run result has this status.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def dry_run(database_env_file: Path | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sca-monitor-db-env-dry-run-") as tmp:
        tmp_path = Path(tmp)
        mode = "provided_file" if database_env_file else "synthetic_split"
        db_env_file = database_env_file or tmp_path / "postgres.env"
        if database_env_file is None:
            db_env_file.write_text(SYNTHETIC_DATABASE_ENV, encoding="utf-8")

        validator = validate(db_env_file)
        result: dict[str, Any] = {
            "status": validator["status"],
            "mode": mode,
            "database_env_file": "provided" if database_env_file else "synthetic",
            "validator": validator,
            "configure": {"status": "skipped"},
            "deployment_readiness": {"status": "skipped"},
        }
        if validator["status"] == "blocked":
            return result

        env_file = tmp_path / "runtime.env"
        env_file.write_text(BASE_RUNTIME_ENV, encoding="utf-8")
        configured = configure(
            env_file,
            public_url=None,
            database_env_file=db_env_file,
            generate_smoke_token=False,
        )
        env = parse_env_file(str(env_file))
        env["_SCA_MONITOR_ENV_FILE_LOADED"] = "1"
        deployment_readiness = readiness(
            env,
            require_postgres=True,
            require_split=True,
            require_runtime_inputs=True,
        )

        result["configure"] = configured
        result["deployment_readiness"] = deployment_readiness
        if deployment_readiness["status"] == "blocked":
            result["status"] = "blocked"
        elif validator["status"] == "action_required" or deployment_readiness["status"] == "action_required":
            result["status"] = "action_required"
        else:
            result["status"] = "ok"
        return result


def main() -> int:
    args = parse_args()
    result = dry_run(Path(args.database_env_file) if args.database_env_file else None)
    if args.expect_status:
        result["expected_status"] = args.expect_status
        result["expectation_met"] = result["status"] == args.expect_status
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"database env dry-run gate: {result['status']}")
        print(f"- validator: {result['validator']['status']}")
        print(f"- configure: {result['configure']['status']}")
        print(f"- deployment readiness: {result['deployment_readiness']['status']}")
        if args.expect_status:
            print(f"- expected status: {args.expect_status}")
    if args.expect_status:
        return 0 if result["expectation_met"] else 2
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
