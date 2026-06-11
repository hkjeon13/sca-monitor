#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.advisory_sync import NVD_CVE_API_URL, load_nvd_modified_cve_ids, sync_nvd_cve, sync_nvd_cves
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
    parser.add_argument("--last-mod-start", default=None, help="NVD lastModStartDate window for incremental candidate discovery")
    parser.add_argument("--last-mod-end", default=None, help="NVD lastModEndDate window for incremental candidate discovery")
    parser.add_argument("--use-cursor", action="store_true", help="Use advisory_sync_state.cursor as lastModStartDate when --last-mod-start is omitted.")
    parser.add_argument("--lookback-hours", type=float, default=24.0, help="Fallback modified-window lookback when --use-cursor has no timestamp cursor.")
    parser.add_argument("--modified-json-path", type=Path, default=None, help="Read a local NVD modified-window response JSON instead of discovering candidates remotely")
    parser.add_argument("--modified-results-per-page", type=int, default=2000, help="NVD modified-window page size for remote candidate discovery.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum CVE ids to process from arguments/list")
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=float(os.getenv("NVD_REQUEST_DELAY_SECONDS", "0")),
        help="Delay between remote NVD CVE requests in batch mode. Defaults to NVD_REQUEST_DELAY_SECONDS or 0.",
    )
    parser.add_argument("--lock-owner", default=None, help="Explicit sync lock owner id")
    parser.add_argument("--lock-ttl-seconds", type=int, default=3600, help="Sync lock time-to-live in seconds")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    cve_ids = list(args.cve_ids)
    modified_window_end = args.last_mod_end
    if args.use_cursor and not args.last_mod_start:
        args.last_mod_start = nvd_cursor_or_fallback_start(app, args.lookback_hours)
    if args.use_cursor and not args.last_mod_end and not args.modified_json_path:
        modified_window_end = nvd_timestamp(datetime.now(timezone.utc))
        args.last_mod_end = modified_window_end
    if args.cve_list_path:
        cve_ids.extend(
            line.strip()
            for line in args.cve_list_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    if args.last_mod_start or args.last_mod_end or args.modified_json_path:
        if not args.modified_json_path and not (args.last_mod_start and args.last_mod_end):
            raise SystemExit("--last-mod-start and --last-mod-end are required unless --modified-json-path is provided")
        cve_ids.extend(
            load_nvd_modified_cve_ids(
                last_mod_start=args.last_mod_start or "fixture-start",
                last_mod_end=modified_window_end or "fixture-end",
                api_url=args.api_url,
                api_key=args.api_key,
                json_path=args.modified_json_path,
                results_per_page=args.modified_results_per_page,
            )
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
            delay_seconds=args.delay_seconds,
            success_cursor=modified_window_end if (args.last_mod_start or args.modified_json_path) else None,
        )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


def nvd_cursor_or_fallback_start(app: ScaMonitorApp, lookback_hours: float) -> str:
    if lookback_hours <= 0:
        raise SystemExit("--lookback-hours must be greater than 0")
    with app.db.connect() as conn:
        row = conn.execute("SELECT cursor FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    cursor = row["cursor"] if row else None
    if cursor and is_nvd_timestamp_cursor(str(cursor)):
        return str(cursor)
    return nvd_timestamp(datetime.now(timezone.utc) - timedelta(hours=lookback_hours))


def is_nvd_timestamp_cursor(value: str) -> bool:
    if "T" not in value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def nvd_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


if __name__ == "__main__":
    main()
