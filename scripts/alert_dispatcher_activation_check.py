#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.alert_preflight import run_alert_dispatcher_activation_check
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check whether live alert dispatcher can be enabled safely.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum eligible alert rows to inspect via dry-run.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app = ScaMonitorApp(load_settings())
    result = run_alert_dispatcher_activation_check(app, limit=args.limit)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ready":
        print("alert dispatcher activation ready: live dispatcher can be enabled")
    else:
        print(f"alert dispatcher activation blocked: {', '.join(result['blocking_failures'])}", file=sys.stderr)
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
