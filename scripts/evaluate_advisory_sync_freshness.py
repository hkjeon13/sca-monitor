#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def is_sqlite_locked_error(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and "database is locked" in str(exc).lower()


def evaluate_with_retries(
    app: ScaMonitorApp | Callable[[], ScaMonitorApp],
    *,
    now: str | None,
    dry_run: bool,
    actor: str,
    attempts: int,
    retry_delay_seconds: float,
) -> dict:
    attempts = max(1, attempts)
    last_error: sqlite3.OperationalError | None = None
    for attempt in range(1, attempts + 1):
        try:
            if callable(app):
                current_app = app()
            else:
                current_app = app
            result = current_app.evaluate_advisory_sync_freshness_alerts(now=now, dry_run=dry_run, actor=actor)
            result["attempts"] = attempt
            return result
        except sqlite3.OperationalError as exc:
            if not is_sqlite_locked_error(exc):
                raise
            last_error = exc
            if attempt < attempts:
                time.sleep(max(0.0, retry_delay_seconds))
    return {
        "status": "deferred",
        "reason": "database_locked",
        "attempts": attempts,
        "dry_run": dry_run,
        "error": str(last_error) if last_error else "database is locked",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or resolve system alerts for stale advisory sync sources.")
    parser.add_argument("--dry-run", action="store_true", help="Report stale sources without writing alert_events")
    parser.add_argument("--actor", default="freshness-scheduler", help="Actor recorded in audit logs")
    parser.add_argument("--now", default=None, help="Override current time for testing, as ISO-8601")
    parser.add_argument("--attempts", type=int, default=3, help="Attempts when SQLite reports a transient database lock")
    parser.add_argument("--retry-delay-seconds", type=float, default=2.0, help="Delay between SQLite lock retry attempts")
    args = parser.parse_args()

    result = evaluate_with_retries(
        lambda: ScaMonitorApp(load_settings(component="worker")),
        now=args.now,
        dry_run=args.dry_run,
        actor=args.actor,
        attempts=args.attempts,
        retry_delay_seconds=args.retry_delay_seconds,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
