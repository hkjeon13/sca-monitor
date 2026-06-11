#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path
from typing import Any


DATABASE_INPUT_KEYS = [
    "MIGRATION_DATABASE_URL",
    "API_DATABASE_URL",
    "WORKER_DATABASE_URL",
    "SCA_MONITOR_DATABASE_URL",
    "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE",
    "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT",
    "SCA_MONITOR_AUTO_MIGRATE",
    "SCA_MONITOR_API_AUTO_MIGRATE",
    "SCA_MONITOR_WORKER_AUTO_MIGRATE",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update runtime deployment inputs in a .env-style file.")
    parser.add_argument("--env-file", required=True, help="Path to the .env-style file to update.")
    parser.add_argument(
        "--database-env-file",
        help="Merge allowlisted PostgreSQL cutover inputs from a remote-only .env-style file.",
    )
    parser.add_argument("--public-url", help="Set SCA_MONITOR_PUBLIC_URL.")
    parser.add_argument(
        "--generate-smoke-token",
        action="store_true",
        help="Generate SMOKE_TEST_TOKEN when missing or still set to change-me.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON without secret values.")
    return parser.parse_args()


def parse_env_lines(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def format_env_line(key: str, value: str) -> str:
    return f"{key}={value}"


def set_env_value(lines: list[str], key: str, value: str) -> tuple[list[str], bool]:
    output: list[str] = []
    replaced = False
    changed = False
    for raw_line in lines:
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line and line.split("=", 1)[0].strip() == key:
            new_line = format_env_line(key, value)
            output.append(new_line)
            replaced = True
            changed = changed or raw_line != new_line
        else:
            output.append(raw_line)
    if not replaced:
        output.append(format_env_line(key, value))
        changed = True
    return output, changed


def configure(
    env_file: Path,
    *,
    public_url: str | None,
    database_env_file: Path | None,
    generate_smoke_token: bool,
) -> dict[str, Any]:
    lines = env_file.read_text(encoding="utf-8").splitlines()
    values = parse_env_lines(lines)
    updated: list[str] = []

    if public_url:
        lines, changed = set_env_value(lines, "SCA_MONITOR_PUBLIC_URL", public_url)
        if changed:
            updated.append("SCA_MONITOR_PUBLIC_URL")

    if generate_smoke_token and values.get("SMOKE_TEST_TOKEN", "") in {"", "change-me"}:
        lines, changed = set_env_value(lines, "SMOKE_TEST_TOKEN", secrets.token_urlsafe(32))
        if changed:
            updated.append("SMOKE_TEST_TOKEN")

    if database_env_file:
        database_values = parse_env_lines(database_env_file.read_text(encoding="utf-8").splitlines())
        for key in DATABASE_INPUT_KEYS:
            if key not in database_values:
                continue
            lines, changed = set_env_value(lines, key, database_values[key])
            if changed:
                updated.append(key)

    if updated:
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {"status": "ok", "env_file": str(env_file), "updated": updated}


def main() -> int:
    args = parse_args()
    result = configure(
        Path(args.env_file),
        public_url=args.public_url,
        database_env_file=Path(args.database_env_file) if args.database_env_file else None,
        generate_smoke_token=args.generate_smoke_token,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"runtime inputs configured: {', '.join(result['updated']) if result['updated'] else 'no changes'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
