#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings
from backend.sca_monitor.endpoint_poll import poll_configured_endpoints


def main() -> None:
    parser = argparse.ArgumentParser(description="Poll configured dependency status endpoints.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum configured endpoints to poll")
    parser.add_argument("--worker-name", default="default", help="Endpoint poll worker lease name")
    parser.add_argument("--lock-owner", help="Explicit lock owner for operational traces")
    parser.add_argument("--lock-ttl-seconds", type=int, default=300, help="Endpoint poll lease TTL")
    parser.add_argument("--no-lock", action="store_true", help="Run without acquiring endpoint poll lease")
    parser.add_argument("--iterations", type=int, default=1, help="Number of poll iterations; use 0 to run forever")
    parser.add_argument("--interval-seconds", type=float, default=0, help="Sleep interval between iterations")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    iteration = 0
    results = []
    while args.iterations == 0 or iteration < args.iterations:
        iteration += 1
        result = poll_configured_endpoints(
            app,
            limit=args.limit,
            worker_name=args.worker_name,
            lock_owner=args.lock_owner,
            lock_ttl_seconds=args.lock_ttl_seconds,
            use_lock=not args.no_lock,
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
