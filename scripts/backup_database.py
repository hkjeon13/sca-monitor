#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
from contextlib import closing
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
    # Reserve a private, unique file: another backup in the same second must
    # not overwrite an existing recovery artifact.
    with tempfile.NamedTemporaryFile(prefix=f"{database.path.stem}-{timestamp}-",
            suffix=database.path.suffix, dir=target_dir, delete=False) as reserved:
        backup_path = Path(reserved.name)
    source = sqlite3.connect(database.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
    try:
        # Pin a consistent snapshot even when collectors are committing. Copying
        # only the main file would omit committed WAL transactions.
        source.execute("BEGIN")
        source.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
        with closing(sqlite3.connect(backup_path)) as destination:
            source.backup(destination, pages=8192)
            if destination.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("SQLite backup integrity check failed")
    finally:
        source.rollback()
        source.close()
    result.update(
        {
            "status": "ok",
            "backup_path": str(backup_path),
            "bytes": backup_path.stat().st_size,
            "verification": "quick_check=ok",
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
