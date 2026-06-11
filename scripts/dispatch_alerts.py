#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
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
    parser.add_argument("--max-retries", type=int, default=5, help="Move alert to dead_letter after this many failed attempts")
    parser.add_argument("--iterations", type=int, default=1, help="Number of dispatch iterations; use 0 to run forever")
    parser.add_argument("--interval-seconds", type=float, default=0, help="Sleep interval between iterations")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings())
    iteration = 0
    results = []
    while args.iterations == 0 or iteration < args.iterations:
        iteration += 1
        result = dispatch_pending_alerts(
            app,
            webhook_url=args.webhook_url,
            limit=args.limit,
            dry_run=args.dry_run,
            lock_owner=args.lock_owner,
            lock_ttl_seconds=args.lock_ttl_seconds,
            retry_backoff_seconds=args.retry_backoff_seconds,
            max_retries=args.max_retries,
        )
        payload = {"iteration": iteration, **result.__dict__}
        results.append(payload)
        if args.iterations == 1:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return
        print(json.dumps(payload, ensure_ascii=False), flush=True)
        if args.iterations != 0 and iteration >= args.iterations:
            break
        if args.interval_seconds > 0:
            time.sleep(args.interval_seconds)

    print(json.dumps({"iterations": results}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
