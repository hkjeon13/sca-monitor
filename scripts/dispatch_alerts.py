#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.alert_dispatch import dispatch_pending_alerts
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Dispatch pending alert_events to a webhook target.")
    parser.add_argument("--webhook-url", default=os.getenv("ALERT_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK_URL"))
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true", help="Count pending alerts without sending or updating rows")
    parser.add_argument("--lock-owner", default=None, help="Explicit dispatch lock owner id")
    parser.add_argument("--lock-ttl-seconds", type=int, default=300, help="Per-alert dispatch lock time-to-live in seconds")
    parser.add_argument("--retry-backoff-seconds", type=int, default=300, help="Base retry backoff in seconds")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings())
    result = dispatch_pending_alerts(
        app,
        webhook_url=args.webhook_url,
        limit=args.limit,
        dry_run=args.dry_run,
        lock_owner=args.lock_owner,
        lock_ttl_seconds=args.lock_ttl_seconds,
        retry_backoff_seconds=args.retry_backoff_seconds,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
