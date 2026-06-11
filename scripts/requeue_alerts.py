#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Requeue dead-letter alert events.")
    parser.add_argument("--alert-event-id", help="Single alert event id to requeue")
    parser.add_argument("--all", action="store_true", help="Requeue dead-letter alerts up to --limit")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--actor", default="operator")
    parser.add_argument("--reason", default="manual dead-letter requeue")
    args = parser.parse_args()

    if not args.alert_event_id and not args.all:
        raise SystemExit("--alert-event-id or --all is required")

    app = ScaMonitorApp(load_settings())
    ids = [args.alert_event_id] if args.alert_event_id else dead_letter_ids(app, args.limit)
    results = [
        app.requeue_alert_event(alert_id, {"actor": args.actor, "reason": args.reason})["alert_event"]
        for alert_id in ids
    ]
    print(json.dumps({"requeued": len(results), "alert_events": results}, ensure_ascii=False, indent=2))


def dead_letter_ids(app: ScaMonitorApp, limit: int) -> list[str]:
    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT id
            FROM alert_events
            WHERE status = 'dead_letter'
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row["id"] for row in rows]


if __name__ == "__main__":
    main()
