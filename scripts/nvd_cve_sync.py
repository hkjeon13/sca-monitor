#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import signal
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.advisory_sync import NVD_CVE_API_URL, NvdAPIClient, NvdWindowChanged, load_nvd_modified_cve_ids, sync_nvd_cve, sync_nvd_cves, sync_nvd_modified_window
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
    parser.add_argument("--window-days", type=float, default=1, help="Checkpoint each completed modified day; smaller windows reduce live pagination drift.")
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
    if (args.last_mod_start and args.last_mod_end and not args.modified_json_path
            and not args.json_path and not args.json_dir and not args.cve_list_path
            and not cve_ids and args.limit is None):
        if not 0 < args.window_days <= 120:
            raise SystemExit("--window-days must be greater than zero and at most 120")
        start = datetime.fromisoformat(args.last_mod_start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(args.last_mod_end.replace("Z", "+00:00"))
        start = start.replace(tzinfo=timezone.utc) if start.tzinfo is None else start
        end = end.replace(tzinfo=timezone.utc) if end.tzinfo is None else end
        if start >= end:
            raise SystemExit("modified window start must precede end")
        windows = []
        client = NvdAPIClient(delay_seconds=args.delay_seconds or (0.7 if args.api_key else 6.2))
        while start < end:
            checkpoint = min(end, start + timedelta(days=args.window_days))
            for attempt in range(3):
                try:
                    result = sync_nvd_modified_window(app, last_mod_start=nvd_timestamp(start),
                        last_mod_end=nvd_timestamp(checkpoint), api_url=args.api_url, api_key=args.api_key,
                        results_per_page=args.modified_results_per_page,
                        delay_seconds=args.delay_seconds or (0.7 if args.api_key else 6.2),
                        lock_ttl_seconds=args.lock_ttl_seconds,
                        client=client,
                        progress=lambda item: print(json.dumps(item), flush=True))
                    break
                except NvdWindowChanged:
                    if attempt == 2:
                        raise
                    print(json.dumps({"event": "nvd_window_retry", "attempt": attempt + 2,
                        "window_start": nvd_timestamp(start), "window_end": nvd_timestamp(checkpoint),
                        "reason": "provider changed pagination; completed cursor retained"}), flush=True)
                    client.sleep(max(client.delay_seconds, 1))
            windows.append(result.__dict__)
            start = checkpoint
        print(json.dumps({"source": "NVD", "failed": 0, "windows": windows,
            "cursor": nvd_timestamp(end)}, ensure_ascii=False), flush=True)
        return
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
        modified_window_requested = bool(args.last_mod_start or args.modified_json_path)
        if not cve_ids and not modified_window_requested:
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
    if getattr(result, "failed", 0):
        raise SystemExit(1)


def nvd_cursor_or_fallback_start(app: ScaMonitorApp, lookback_hours: float) -> str:
    if lookback_hours <= 0:
        raise SystemExit("--lookback-hours must be greater than 0")
    with app.db.connect() as conn:
        row = conn.execute("SELECT cursor,last_success_at FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    cursor = row["cursor"] if row else None
    if cursor and is_nvd_timestamp_cursor(str(cursor)):
        value = datetime.fromisoformat(str(cursor).replace("Z", "+00:00"))
        return nvd_timestamp(value - timedelta(minutes=5))
    if row and row["last_success_at"] and is_nvd_timestamp_cursor(str(row["last_success_at"])):
        value = datetime.fromisoformat(str(row["last_success_at"]).replace("Z", "+00:00"))
        return nvd_timestamp(value - timedelta(minutes=5))
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
    def interrupted(signum, frame):
        raise KeyboardInterrupt("NVD collection interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    main()
