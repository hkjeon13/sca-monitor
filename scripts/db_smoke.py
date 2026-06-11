#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.config import load_settings
from backend.sca_monitor.db import Database, utcnow


def run_smoke(database: Database, *, write_check: bool = True) -> dict[str, Any]:
    readiness = database.readiness()
    migration = readiness["migration"]
    result: dict[str, Any] = {
        "status": "ok",
        "database_backend": readiness["database_backend"],
        "migration": migration,
        "checks": {},
    }
    if not migration["compatible"]:
        result["status"] = "failed"
        result["error"] = "migration_too_old"
        return result
    if database.backend != "sqlite":
        result["status"] = "failed"
        result["error"] = "query_adapter_not_enabled"
        result["detail"] = "PostgreSQL migration status is readable, but runtime query adapter is not enabled yet."
        return result

    with database.connect() as conn:
        result["checks"]["services_readable"] = conn.execute("SELECT COUNT(*) AS c FROM services").fetchone()["c"] >= 0
        result["checks"]["advisory_sync_state_readable"] = conn.execute(
            "SELECT COUNT(*) AS c FROM advisory_sync_state"
        ).fetchone()["c"] >= 0
        result["checks"]["alert_events_readable"] = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_events"
        ).fetchone()["c"] >= 0
        if write_check:
            smoke_id = f"db-smoke-{uuid.uuid4()}"
            conn.execute("BEGIN")
            conn.execute(
                """
                INSERT INTO audit_logs (
                    id, actor, action, target_type, target_id, reason, before_state, after_state, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    smoke_id,
                    "db-smoke",
                    "db.smoke.write",
                    "database",
                    "connectivity",
                    "transaction rollback smoke check",
                    "{}",
                    "{}",
                    utcnow(),
                ),
            )
            row = conn.execute("SELECT id FROM audit_logs WHERE id = ?", (smoke_id,)).fetchone()
            result["checks"]["audit_log_write_rollback"] = row is not None
            conn.rollback()
            row_after_rollback = conn.execute("SELECT id FROM audit_logs WHERE id = ?", (smoke_id,)).fetchone()
            result["checks"]["audit_log_rollback_clean"] = row_after_rollback is None
    if not all(result["checks"].values()):
        result["status"] = "failed"
        result["error"] = "smoke_check_failed"
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SCA Monitor database connectivity and schema smoke checks.")
    parser.add_argument("--database-url", help="Override SCA_MONITOR_DATABASE_URL/API_DATABASE_URL for this check.")
    parser.add_argument("--read-only", action="store_true", help="Skip transactional write/rollback check.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings = load_settings()
    database = Database(args.database_url or settings.database_url)
    try:
        result = run_smoke(database, write_check=not args.read_only)
    except Exception as exc:  # noqa: BLE001 - deployment smoke should expose the exact failure.
        result = {
            "status": "failed",
            "database_backend": database.backend,
            "error": exc.__class__.__name__,
            "detail": str(exc),
        }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ok":
        checks = ", ".join(name for name, ok in result["checks"].items() if ok)
        print(
            "db smoke ok: "
            f"backend={result['database_backend']} "
            f"migration={result['migration']['current']}/{result['migration']['required']} "
            f"checks={checks}"
        )
    else:
        detail = f": {result['detail']}" if result.get("detail") else ""
        print(f"db smoke failed: backend={result['database_backend']} error={result.get('error')}{detail}", file=sys.stderr)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
