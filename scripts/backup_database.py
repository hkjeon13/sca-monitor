#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.config import load_settings
from backend.sca_monitor.db import Database


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a pre-migration database backup for SQLite fallback deployments.")
    parser.add_argument("--backup-dir", help="Directory for backup files. Defaults to SCA_MONITOR_DATA_DIR/backups.")
    parser.add_argument("--required", action="store_true", help="Fail when a backup cannot be created.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def backup_database(*, backup_dir: Path | None, required: bool) -> dict:
    settings = load_settings()
    database = Database(settings.database_url)
    result = {
        "status": "skipped",
        "database_backend": database.backend,
        "database_url_source": settings.database_url_source,
        "backup_path": None,
    }
    if database.backend != "sqlite":
        result["reason"] = "backup managed outside application for PostgreSQL"
        if required:
            result["status"] = "blocked"
        return result
    if database.path is None or not database.path.exists():
        result["reason"] = "SQLite database file does not exist yet"
        if required:
            result["status"] = "blocked"
        return result

    target_dir = (backup_dir or (settings.data_dir / "backups")).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = target_dir / f"{database.path.stem}-{timestamp}{database.path.suffix}"
    shutil.copy2(database.path, backup_path)
    result.update(
        {
            "status": "ok",
            "backup_path": str(backup_path),
            "bytes": backup_path.stat().st_size,
        }
    )
    return result


def main() -> int:
    args = parse_args()
    result = backup_database(backup_dir=Path(args.backup_dir) if args.backup_dir else None, required=args.required)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"database backup: {result['status']}")
        if result.get("backup_path"):
            print(f"- backup_path: {result['backup_path']}")
        if result.get("reason"):
            print(f"- reason: {result['reason']}")
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
