#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.alert_dispatch import send_webhook


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a synthetic SCA Monitor alert webhook smoke payload.")
    parser.add_argument("--webhook-url", default=os.getenv("ALERT_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK_URL"))
    parser.add_argument("--service-id", default="sca-monitor-webhook-smoke")
    parser.add_argument("--environment", default=os.getenv("APP_ENV", "smoke"))
    parser.add_argument("--advisory-id", default="SMOKE-ALERT-WEBHOOK")
    parser.add_argument("--package-name", default="synthetic-package")
    parser.add_argument("--risk-level", default="low")
    parser.add_argument("--json", action="store_true", help="Print machine-readable result JSON.")
    args = parser.parse_args()

    if not args.webhook_url:
        print("webhook_url required: pass --webhook-url or set ALERT_WEBHOOK_URL/SLACK_WEBHOOK_URL", file=sys.stderr)
        return 2

    smoke_id = f"webhook-smoke-{uuid4()}"
    payload = {
        "smoke": True,
        "smoke_id": smoke_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "service_id": args.service_id,
        "environment": args.environment,
        "advisory_id": args.advisory_id,
        "package_name": args.package_name,
        "risk_level": args.risk_level,
        "summary": "Synthetic SCA Monitor webhook smoke event",
    }
    headers = {
        "Idempotency-Key": smoke_id,
        "X-SCA-Alert-Event-Id": smoke_id,
        "X-SCA-Alert-Suppression-Key": f"{args.service_id}:{args.environment}:{args.advisory_id}:{args.package_name}:{args.risk_level}:smoke",
        "X-SCA-Smoke": "true",
    }

    send_webhook(args.webhook_url, payload, headers)
    result = {"status": "ok", "smoke_id": smoke_id, "webhook_url": mask_url(args.webhook_url)}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"alert webhook smoke ok: smoke_id={smoke_id} webhook_url={result['webhook_url']}")
    return 0


def mask_url(value: str) -> str:
    if "://" not in value:
        return "***"
    scheme, rest = value.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/..."


if __name__ == "__main__":
    raise SystemExit(main())
