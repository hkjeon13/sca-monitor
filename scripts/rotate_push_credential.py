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
    parser = argparse.ArgumentParser(description="Rotate a service push credential.")
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--credential-id", required=True)
    parser.add_argument("--environment", default="prod")
    parser.add_argument("--ttl-days", type=int, default=None)
    parser.add_argument("--actor", default="operator")
    parser.add_argument("--reason", default="push credential rotation")
    args = parser.parse_args()

    body = {
        "environment": args.environment,
        "actor": args.actor,
        "reason": args.reason,
    }
    if args.ttl_days is not None:
        body["ttl_days"] = args.ttl_days

    app = ScaMonitorApp(load_settings())
    result = app.rotate_push_credential(args.service_id, args.credential_id, body)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
