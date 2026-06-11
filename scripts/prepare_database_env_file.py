#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.validate_database_env_file import validate


DEFAULT_TEMPLATE = Path(REPO_ROOT) / "deploy" / "postgres.env.example"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a protected PostgreSQL env template without printing secrets.")
    parser.add_argument(
        "--database-env-file",
        default=".secrets/postgres.env",
        help="Target PostgreSQL env file to create. Defaults to .secrets/postgres.env.",
    )
    parser.add_argument(
        "--template",
        default=str(DEFAULT_TEMPLATE),
        help="Template env file to copy. Defaults to deploy/postgres.env.example.",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite an existing target file.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def check(status: str, check_id: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "status": status, "detail": detail}


def prepare(target: Path, template: Path, *, force: bool) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    if not template.exists():
        checks.append(check("blocker", "template_file", "template file does not exist"))
        return {
            "status": "blocked",
            "database_env_file": "not_configured",
            "mode": None,
            "checks": checks,
            "validator": None,
        }

    if target.exists() and not force:
        checks.append(check("blocker", "existing_file", "database env file already exists; use --force to overwrite"))
        try:
            current_mode = oct(stat.S_IMODE(target.stat().st_mode))
        except OSError:
            current_mode = None
        return {
            "status": "blocked",
            "database_env_file": "configured",
            "mode": current_mode,
            "checks": checks,
            "validator": None,
        }

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    target.chmod(0o600)
    checks.append(check("ok", "file_created", "database env file created with protected permissions"))
    validator = validate(target)
    return {
        "status": "created" if not force else "overwritten",
        "database_env_file": "configured",
        "mode": oct(stat.S_IMODE(target.stat().st_mode)),
        "checks": checks,
        "validator": validator,
    }


def main() -> int:
    args = parse_args()
    result = prepare(Path(args.database_env_file), Path(args.template), force=args.force)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"database env file prepare: {result['status']}")
        for item in result["checks"]:
            print(f"- {item['status']}: {item['id']}: {item['detail']}")
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
