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
from backend.sca_monitor.endpoint_poll import poll_configured_endpoints


def main() -> None:
    parser = argparse.ArgumentParser(description="Poll configured dependency status endpoints once.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum configured endpoints to poll")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings())
    result = poll_configured_endpoints(app, limit=args.limit)
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
