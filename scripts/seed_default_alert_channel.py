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

from backend.sca_monitor.alert_preflight import default_channel_summary, is_placeholder_url
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def env_webhook_url() -> str | None:
    return (
        os.getenv("SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL")
        or os.getenv("DEFAULT_ALERT_CHANNEL_URL")
        or os.getenv("ALERT_WEBHOOK_URL")
        or os.getenv("SLACK_WEBHOOK_URL")
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed or update the enabled default webhook alert channel.")
    parser.add_argument("--name", default=os.getenv("SCA_MONITOR_DEFAULT_ALERT_CHANNEL_NAME", "default-webhook"))
    parser.add_argument("--webhook-url", default=env_webhook_url())
    parser.add_argument("--actor", default="bootstrap")
    parser.add_argument("--reason", default="default alert channel seed")
    parser.add_argument("--allow-placeholder", action="store_true", help="Allow example/test webhook hosts for dev fixtures.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def error(message: str, *, json_output: bool) -> int:
    if json_output:
        print(json.dumps({"status": "error", "error": message}, ensure_ascii=False, indent=2))
    else:
        print(message, file=sys.stderr)
    return 2


def main() -> int:
    args = parse_args()
    if not args.webhook_url:
        return error(
            "webhook_url required: pass --webhook-url or set SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL",
            json_output=args.json,
        )
    if is_placeholder_url(args.webhook_url) and not args.allow_placeholder:
        return error(
            "placeholder webhook target rejected: provide a real alert router URL or pass --allow-placeholder for dev",
            json_output=args.json,
        )

    app = ScaMonitorApp(load_settings())
    before = default_channel_summary(app)
    result = app.create_alert_channel(
        {
            "name": args.name,
            "channel_type": "webhook",
            "target_url": args.webhook_url,
            "enabled": True,
            "is_default": True,
            "actor": args.actor,
            "reason": args.reason,
        }
    )
    after = default_channel_summary(app)
    payload = {
        "status": "ok",
        "before": before,
        "after": after,
        "channel": result["channel"],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(
            "default alert channel seeded: "
            f"name={result['channel']['name']} target={result['channel']['target_url_masked']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
