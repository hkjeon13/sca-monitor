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
    parser = argparse.ArgumentParser(description="Create alert outbox rows for overdue SLA impacts.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum active impacts to scan")
    parser.add_argument("--dry-run", action="store_true", help="Report candidates without writing alert_events")
    parser.add_argument("--actor", default="sla-scheduler", help="Actor recorded in audit logs")
    parser.add_argument("--now", default=None, help="Override current time for testing, as ISO-8601")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    result = app.enqueue_sla_expired_alerts(now=args.now, limit=args.limit, dry_run=args.dry_run, actor=args.actor)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
