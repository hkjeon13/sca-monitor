#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.alert_dispatch import dispatch_pending_alerts
from backend.sca_monitor.app import ScaMonitorApp, mask_url
from backend.sca_monitor.config import load_settings


def alert_event_counts(app: ScaMonitorApp) -> dict[str, int]:
    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM alert_events
            GROUP BY status
            ORDER BY status
            """
        ).fetchall()
    return {row["status"]: int(row["count"]) for row in rows}


def default_channel_summary(app: ScaMonitorApp) -> dict[str, Any]:
    with app.db.connect() as conn:
        row = conn.execute(
            """
            SELECT id, name, channel_type, target_url, enabled, is_default, updated_at
            FROM alert_channels
            WHERE enabled = 1 AND is_default = 1 AND channel_type = 'webhook'
            ORDER BY updated_at DESC
            LIMIT 1
            """
        ).fetchone()
    if not row:
        return {"configured": False}
    return {
        "configured": True,
        "id": row["id"],
        "name": row["name"],
        "channel_type": row["channel_type"],
        "target_url_masked": mask_url(row["target_url"]),
    }


def run_preflight(app: ScaMonitorApp, *, limit: int, require_default_channel: bool = True) -> dict[str, Any]:
    readiness = app.db.readiness()
    channel = default_channel_summary(app)
    dry_run = dispatch_pending_alerts(app, webhook_url=None, limit=limit, dry_run=True)
    counts = alert_event_counts(app)
    checks = {
        "database_ready": readiness["database"] == "ok",
        "default_alert_channel_configured": bool(channel["configured"]),
        "dispatcher_dry_run_ok": True,
    }
    if not require_default_channel:
        checks["default_alert_channel_configured"] = True
    status = "ok" if all(checks.values()) else "failed"
    result = {
        "status": status,
        "checks": checks,
        "database": readiness,
        "default_alert_channel": channel,
        "dry_run": dry_run.__dict__,
        "alert_events": counts,
    }
    if status != "ok":
        failures = [name for name, passed in checks.items() if not passed]
        result["failures"] = failures
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run live alert dispatcher preflight without sending alerts.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum eligible alert rows to inspect via dry-run.")
    parser.add_argument(
        "--allow-missing-default-channel",
        action="store_true",
        help="Do not fail when no enabled default webhook channel is configured.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app = ScaMonitorApp(load_settings())
    result = run_preflight(app, limit=args.limit, require_default_channel=not args.allow_missing_default_channel)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ok":
        channel = result["default_alert_channel"]
        channel_text = channel.get("target_url_masked") if channel.get("configured") else "not configured"
        print(
            "alert dispatcher preflight ok: "
            f"pending={result['dry_run']['pending']} "
            f"default_channel={channel_text}"
        )
    else:
        print(f"alert dispatcher preflight failed: {', '.join(result['failures'])}", file=sys.stderr)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
