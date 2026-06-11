#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.advisory_sync import sync_osv_ecosystem_dump
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync OSV advisory dump into the local SCA Monitor database.")
    parser.add_argument("--ecosystem", default="npm", help="OSV ecosystem dump name, for example npm, PyPI, Maven, Go")
    parser.add_argument("--limit", type=int, default=None, help="Maximum advisory JSON files to import from the dump")
    parser.add_argument("--dump-url", default=None, help="Override OSV dump URL")
    parser.add_argument("--zip-path", type=Path, default=None, help="Read a local OSV dump ZIP instead of downloading")
    parser.add_argument("--lock-owner", default=None, help="Explicit sync lock owner id")
    parser.add_argument("--lock-ttl-seconds", type=int, default=3600, help="Sync lock time-to-live in seconds")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings())
    result = sync_osv_ecosystem_dump(
        app,
        args.ecosystem,
        limit=args.limit,
        dump_url=args.dump_url,
        zip_path=args.zip_path,
        lock_owner=args.lock_owner,
        lock_ttl_seconds=args.lock_ttl_seconds,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
