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

from backend.sca_monitor.advisory_sync import NVD_CVE_API_URL, sync_nvd_cve
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync a single NVD CVE 2.0 record into the local SCA Monitor database.")
    parser.add_argument("cve_id", help="CVE id to import, for example CVE-2026-0001")
    parser.add_argument("--api-url", default=NVD_CVE_API_URL, help="Override NVD CVE API 2.0 URL")
    parser.add_argument("--api-key", default=os.getenv("NVD_API_KEY"), help="NVD API key. Defaults to NVD_API_KEY.")
    parser.add_argument("--json-path", type=Path, default=None, help="Read a local NVD CVE API response JSON instead of downloading")
    parser.add_argument("--lock-owner", default=None, help="Explicit sync lock owner id")
    parser.add_argument("--lock-ttl-seconds", type=int, default=3600, help="Sync lock time-to-live in seconds")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    result = sync_nvd_cve(
        app,
        args.cve_id,
        api_url=args.api_url,
        api_key=args.api_key,
        json_path=args.json_path,
        lock_owner=args.lock_owner,
        lock_ttl_seconds=args.lock_ttl_seconds,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
