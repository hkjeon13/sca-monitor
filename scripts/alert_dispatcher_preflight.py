#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.alert_preflight import run_alert_dispatcher_preflight
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


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
    result = run_alert_dispatcher_preflight(app, limit=args.limit, require_default_channel=not args.allow_missing_default_channel)
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
