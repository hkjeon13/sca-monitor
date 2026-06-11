#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.sca_monitor.postgres_cutover import assess_cutover, summarize_preflight


VALID_SYSTEMD_MODES = {"off", "validate", "install", "enable-api", "enable-poller", "enable-dispatcher-dry-run", "enable"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate deployment input environment before SCA Monitor deployment.")
    parser.add_argument("--env-file", help="Read deployment inputs from a .env-style file.")
    parser.add_argument("--require-postgres", action="store_true", help="Fail unless PostgreSQL cutover inputs are ready.")
    parser.add_argument("--require-split", action="store_true", help="Fail unless split PostgreSQL credentials are ready.")
    parser.add_argument(
        "--require-runtime-inputs",
        action="store_true",
        help="Fail unless runtime deployment inputs such as public URL and smoke token are production-ready.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def parse_env_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    values: dict[str, str] = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            values[key] = value
    return values


def check(status: str, check_id: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "status": status, "detail": detail}


def public_url_check(env: dict[str, str], *, required: bool) -> dict[str, str]:
    if env.get("SCA_MONITOR_PUBLIC_URL") or env.get("FRONTEND_PUBLIC_URL"):
        return check("ok", "public_url", "public URL configured")
    status = "blocker" if required else "warning"
    return check(status, "public_url", "SCA_MONITOR_PUBLIC_URL or FRONTEND_PUBLIC_URL is not configured")


def port_check(env: dict[str, str]) -> dict[str, str]:
    raw = env.get("SCA_MONITOR_PORT", "")
    try:
        port = int(raw)
    except ValueError:
        return check("blocker", "port", "SCA_MONITOR_PORT must be an integer")
    if 1 <= port <= 65535:
        return check("ok", "port", "SCA_MONITOR_PORT is valid")
    return check("blocker", "port", "SCA_MONITOR_PORT must be between 1 and 65535")


def systemd_mode_check(env: dict[str, str]) -> dict[str, str]:
    mode = env.get("SCA_MONITOR_SYSTEMD_MODE", "validate")
    if mode in VALID_SYSTEMD_MODES:
        return check("ok", "systemd_mode", f"SCA_MONITOR_SYSTEMD_MODE={mode}")
    return check("blocker", "systemd_mode", f"invalid SCA_MONITOR_SYSTEMD_MODE: {mode}")


def smoke_token_check(env: dict[str, str], *, required: bool) -> dict[str, str]:
    token = env.get("SMOKE_TEST_TOKEN", "")
    if not token:
        return check("blocker" if required else "warning", "smoke_token", "SMOKE_TEST_TOKEN is not configured")
    if env.get("APP_ENV") == "prod" and token == "change-me":
        status = "blocker" if required else "warning"
        return check(status, "smoke_token", "SMOKE_TEST_TOKEN still uses placeholder value")
    return check("ok", "smoke_token", "SMOKE_TEST_TOKEN configured")


def readiness(
    env: dict[str, str],
    *,
    require_postgres: bool,
    require_split: bool,
    require_runtime_inputs: bool,
) -> dict[str, Any]:
    cutover = assess_cutover(env, require_postgres=False, require_split=False)
    required_cutover = assess_cutover(env, require_postgres=require_postgres, require_split=require_split)
    postgres_summary = summarize_preflight(cutover, required_cutover)
    checks = [
        public_url_check(env, required=require_runtime_inputs),
        port_check(env),
        systemd_mode_check(env),
        smoke_token_check(env, required=require_runtime_inputs),
    ]
    postgres_status = required_cutover["status"]
    checks.append(
        check(
            "blocker" if postgres_status == "blocked" else "ok",
            "postgres_cutover",
            postgres_summary["next_action"],
        )
    )
    blockers = [item for item in checks if item["status"] == "blocker"]
    warnings = [item for item in checks if item["status"] == "warning"]
    return {
        "status": "blocked" if blockers else "action_required" if warnings else "ok",
        "env_file": "configured" if env.get("_SCA_MONITOR_ENV_FILE_LOADED") else "not_configured",
        "require_postgres": require_postgres,
        "require_split": require_split,
        "require_runtime_inputs": require_runtime_inputs,
        "checks": checks,
        "postgres": {
            "status": required_cutover["status"],
            "mode": required_cutover["mode"],
            "preflight": postgres_summary,
            "checks": required_cutover["checks"],
        },
    }


def main() -> int:
    args = parse_args()
    file_env = parse_env_file(args.env_file)
    if args.env_file:
        file_env["_SCA_MONITOR_ENV_FILE_LOADED"] = "1"
    env = file_env
    env.update(os.environ)
    result = readiness(
        env,
        require_postgres=args.require_postgres,
        require_split=args.require_split,
        require_runtime_inputs=args.require_runtime_inputs,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"deployment input readiness: {result['status']}")
        for item in result["checks"]:
            print(f"- {item['status']}: {item['id']}: {item['detail']}")
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
