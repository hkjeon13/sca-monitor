#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.db import Database
from scripts.db_smoke import run_smoke


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify that a SQLite backup can be restored and read.")
    parser.add_argument("--backup-path", required=True, help="SQLite backup file to verify.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON without backup file paths.")
    return parser.parse_args()


def verify_backup_restore(backup_path: Path) -> dict[str, Any]:
    if not backup_path.exists():
        return {
            "status": "failed",
            "database_backend": "sqlite",
            "backup_path": "missing",
            "restore_copy_path": None,
            "error": "backup_not_found",
        }
    if not backup_path.is_file():
        return {
            "status": "failed",
            "database_backend": "sqlite",
            "backup_path": "invalid",
            "restore_copy_path": None,
            "error": "backup_is_not_file",
        }

    with tempfile.TemporaryDirectory(prefix="sca-monitor-restore-check-") as tmp_dir:
        restore_copy = Path(tmp_dir) / "restore-check.sqlite3"
        shutil.copy2(backup_path, restore_copy)
        database = Database(f"sqlite:///{restore_copy}")
        try:
            smoke = run_smoke(database, write_check=False)
        except Exception as exc:  # noqa: BLE001 - restore checks should expose the exact blocker class.
            smoke = {"status": "failed", "error": exc.__class__.__name__, "detail": str(exc)}
        return {
            "status": "ok" if smoke.get("status") == "ok" else "failed",
            "database_backend": database.backend,
            "backup_path": "configured",
            "restore_copy_path": "temporary",
            "bytes": backup_path.stat().st_size,
            "smoke": smoke,
        }


def main() -> int:
    args = parse_args()
    result = verify_backup_restore(Path(args.backup_path))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ok":
        migration = result["smoke"]["migration"]
        print(
            "backup restore check ok: "
            f"backend={result['database_backend']} "
            f"migration={migration['current']}/{migration['required']}"
        )
    else:
        detail = f": {result.get('smoke', {}).get('detail') or result.get('error')}"
        print(f"backup restore check failed{detail}", file=sys.stderr)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
