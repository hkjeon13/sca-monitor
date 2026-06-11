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

from backend.sca_monitor.advisory_sync import GITHUB_ADVISORIES_API_URL, sync_github_advisories
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync GitHub Security Advisories into the local SCA Monitor database.")
    parser.add_argument("--api-url", default=GITHUB_ADVISORIES_API_URL, help="Override GitHub Global Security Advisories API URL")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token. Defaults to GITHUB_TOKEN.")
    parser.add_argument("--json-path", type=Path, default=None, help="Read a local GitHub advisories JSON response instead of downloading")
    parser.add_argument("--limit", type=int, default=100, help="Maximum advisory records to process")
    parser.add_argument("--type", dest="advisory_type", default=None, choices=["reviewed", "malware", "unreviewed"], help="GitHub advisory type")
    parser.add_argument("--ecosystem", default=None, help="Filter by GitHub advisory ecosystem, for example npm or pip")
    parser.add_argument("--severity", default=None, choices=["low", "medium", "high", "critical"], help="Filter by advisory severity")
    parser.add_argument("--ghsa-id", default=None, help="Filter by GHSA id")
    parser.add_argument("--cve-id", default=None, help="Filter by CVE id")
    parser.add_argument("--modified", default=None, help="Filter by modified date/range supported by GitHub API")
    parser.add_argument("--published", default=None, help="Filter by published date/range supported by GitHub API")
    parser.add_argument("--updated", default=None, help="Filter by updated date/range supported by GitHub API")
    parser.add_argument("--sort", default="updated", choices=["updated", "published"], help="Sort field")
    parser.add_argument("--direction", default="desc", choices=["asc", "desc"], help="Sort direction")
    parser.add_argument("--lock-owner", default=None, help="Explicit sync lock owner id")
    parser.add_argument("--lock-ttl-seconds", type=int, default=3600, help="Sync lock time-to-live in seconds")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    result = sync_github_advisories(
        app,
        api_url=args.api_url,
        token=args.token,
        json_path=args.json_path,
        limit=args.limit,
        advisory_type=args.advisory_type,
        ecosystem=args.ecosystem,
        severity=args.severity,
        ghsa_id=args.ghsa_id,
        cve_id=args.cve_id,
        modified=args.modified,
        published=args.published,
        updated=args.updated,
        sort=args.sort,
        direction=args.direction,
        lock_owner=args.lock_owner,
        lock_ttl_seconds=args.lock_ttl_seconds,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
