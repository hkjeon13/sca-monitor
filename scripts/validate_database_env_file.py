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
from scripts.configure_runtime_inputs import DATABASE_INPUT_KEYS, parse_env_lines


PLACEHOLDER_MARKERS = ("<", ">", "change-me", "example")
REQUIRED_SPLIT_KEYS = ("MIGRATION_DATABASE_URL", "API_DATABASE_URL", "WORKER_DATABASE_URL")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a PostgreSQL database env file without printing secret values.")
    parser.add_argument("--database-env-file", required=True, help="Path to the database .env-style file to validate.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def check(status: str, check_id: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "status": status, "detail": detail}


def has_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def file_permission_check(path: Path) -> dict[str, str]:
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        return check(
            "blocker",
            "file_permissions",
            f"database env file must not grant group/other permissions; current mode is {oct(mode)}",
        )
    return check("ok", "file_permissions", f"database env file mode is {oct(mode)}")


def validate(path: Path) -> dict[str, Any]:
    values = parse_env_lines(path.read_text(encoding="utf-8").splitlines())
    allowed_values = {key: values[key] for key in DATABASE_INPUT_KEYS if key in values}
    checks: list[dict[str, str]] = []
    checks.append(file_permission_check(path))

    missing = [key for key in REQUIRED_SPLIT_KEYS if key not in allowed_values]
    if missing:
        checks.append(check("blocker", "required_keys", f"missing required keys: {', '.join(missing)}"))
    else:
        checks.append(check("ok", "required_keys", "required split database URL keys are present"))

    placeholder_keys = [key for key, value in allowed_values.items() if has_placeholder(value)]
    if placeholder_keys:
        checks.append(check("blocker", "placeholder_values", f"placeholder values remain for: {', '.join(placeholder_keys)}"))
    else:
        checks.append(check("ok", "placeholder_values", "no placeholder values detected"))

    cutover = assess_cutover(allowed_values, require_postgres=False, require_split=False)
    required_cutover = assess_cutover(allowed_values, require_postgres=True, require_split=True)
    cutover_summary = summarize_preflight(cutover, required_cutover)
    checks.extend(required_cutover["checks"])

    blockers = [item for item in checks if item["status"] == "blocker"]
    warnings = [item for item in checks if item["status"] == "warning"]
    return {
        "status": "blocked" if blockers else "action_required" if warnings else "ok",
        "database_env_file": "configured",
        "summary": {
            "allowed_keys": len(allowed_values),
            "ignored_keys": len([key for key in values if key not in DATABASE_INPUT_KEYS]),
            "blockers": len(blockers),
            "warnings": len(warnings),
        },
        "checks": checks,
        "cutover": {
            "status": required_cutover["status"],
            "mode": required_cutover["mode"],
            "preflight": cutover_summary,
        },
    }


def main() -> int:
    args = parse_args()
    result = validate(Path(args.database_env_file))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"database env readiness: {result['status']}")
        for item in result["checks"]:
            print(f"- {item['status']}: {item['id']}: {item['detail']}")
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
