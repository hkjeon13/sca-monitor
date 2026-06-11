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

from backend.sca_monitor.advisory_sync import NVD_CVE_API_URL, sync_nvd_cve, sync_nvd_cves
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync NVD CVE 2.0 records into the local SCA Monitor database.")
    parser.add_argument("cve_ids", nargs="*", help="CVE ids to import, for example CVE-2026-0001 CVE-2026-0002")
    parser.add_argument("--api-url", default=NVD_CVE_API_URL, help="Override NVD CVE API 2.0 URL")
    parser.add_argument("--api-key", default=os.getenv("NVD_API_KEY"), help="NVD API key. Defaults to NVD_API_KEY.")
    parser.add_argument("--json-path", type=Path, default=None, help="Read a local NVD CVE API response JSON instead of downloading")
    parser.add_argument("--json-dir", type=Path, default=None, help="Read local NVD CVE API response files named CVE-YYYY-NNNN.json")
    parser.add_argument("--cve-list-path", type=Path, default=None, help="Read CVE ids from a newline-delimited text file")
    parser.add_argument("--limit", type=int, default=None, help="Maximum CVE ids to process from arguments/list")
    parser.add_argument("--lock-owner", default=None, help="Explicit sync lock owner id")
    parser.add_argument("--lock-ttl-seconds", type=int, default=3600, help="Sync lock time-to-live in seconds")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    cve_ids = list(args.cve_ids)
    if args.cve_list_path:
        cve_ids.extend(
            line.strip()
            for line in args.cve_list_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    if args.json_path:
        if len(cve_ids) != 1:
            raise SystemExit("--json-path requires exactly one CVE id")
        result = sync_nvd_cve(
            app,
            cve_ids[0],
            api_url=args.api_url,
            api_key=args.api_key,
            json_path=args.json_path,
            lock_owner=args.lock_owner,
            lock_ttl_seconds=args.lock_ttl_seconds,
        )
    else:
        if not cve_ids:
            raise SystemExit("at least one CVE id or --cve-list-path is required")
        result = sync_nvd_cves(
            app,
            cve_ids,
            api_url=args.api_url,
            api_key=args.api_key,
            json_dir=args.json_dir,
            limit=args.limit,
            lock_ttl_seconds=args.lock_ttl_seconds,
        )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
