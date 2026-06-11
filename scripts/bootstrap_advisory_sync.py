#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.advisory_sync import CISA_KEV_CATALOG_URL, sync_cisa_kev_catalog, sync_osv_ecosystem_dump
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def run_bootstrap_advisory_sync(app: ScaMonitorApp, args: argparse.Namespace) -> dict[str, Any]:
    tasks: list[dict[str, Any]] = []
    for name, runner in (
        ("osv", run_osv_sync),
        ("cisa_kev", run_cisa_kev_sync),
        ("openssf", run_openssf_sync),
    ):
        if name in args.skip_source:
            tasks.append({"name": name, "status": "skipped"})
            continue
        try:
            result = runner(app, args)
            status = "partial" if result.get("failed", 0) or result.get("scan_limit_reached") else "ok"
            tasks.append({"name": name, "status": status, "result": result})
        except Exception as exc:  # noqa: BLE001 - bootstrap automation must report exact source failure.
            tasks.append(
                {
                    "name": name,
                    "status": "error",
                    "error": exc.__class__.__name__,
                    "detail": str(exc),
                }
            )
            if args.stop_on_error:
                break
    advisory_readiness = app.overview()["advisory_sync_readiness"]
    blocking = [task["name"] for task in tasks if task["status"] not in {"ok", "skipped"}]
    if not blocking and advisory_readiness["status"] != "ready":
        blocking.append("advisory_sync_readiness")
    return {
        "status": "ok" if not blocking else "blocked",
        "blocking_sources": blocking,
        "tasks": tasks,
        "advisory_sync_readiness": advisory_readiness,
        "next_action": "check_bootstrap_readiness" if not blocking else "resolve_failed_sources",
    }


def run_osv_sync(app: ScaMonitorApp, args: argparse.Namespace) -> dict[str, Any]:
    return asdict(
        sync_osv_ecosystem_dump(
            app,
            args.ecosystem,
            limit=args.osv_limit,
            dump_url=args.osv_dump_url,
            zip_path=args.osv_zip_path,
            lock_owner=args.lock_owner_prefix and f"{args.lock_owner_prefix}-osv",
            lock_ttl_seconds=args.lock_ttl_seconds,
            source="OSV",
        )
    )


def run_cisa_kev_sync(app: ScaMonitorApp, args: argparse.Namespace) -> dict[str, Any]:
    return asdict(
        sync_cisa_kev_catalog(
            app,
            limit=args.cisa_limit,
            catalog_url=args.cisa_catalog_url or CISA_KEV_CATALOG_URL,
            json_path=args.cisa_json_path,
            lock_owner=args.lock_owner_prefix and f"{args.lock_owner_prefix}-cisa-kev",
            lock_ttl_seconds=args.lock_ttl_seconds,
        )
    )


def run_openssf_sync(app: ScaMonitorApp, args: argparse.Namespace) -> dict[str, Any]:
    return asdict(
        sync_osv_ecosystem_dump(
            app,
            args.ecosystem,
            limit=args.openssf_limit,
            dump_url=args.openssf_dump_url or args.osv_dump_url,
            zip_path=args.openssf_zip_path or args.osv_zip_path,
            lock_owner=args.lock_owner_prefix and f"{args.lock_owner_prefix}-openssf",
            lock_ttl_seconds=args.lock_ttl_seconds,
            source="OpenSSF",
            malicious_only=True,
            scan_limit=args.openssf_scan_limit,
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run initial advisory source syncs required for SCA Monitor bootstrap.")
    parser.add_argument("--ecosystem", default="npm", help="OSV ecosystem dump name for OSV and OpenSSF bootstrap syncs.")
    parser.add_argument("--osv-limit", type=int, default=None, help="Maximum OSV records to import.")
    parser.add_argument("--cisa-limit", type=int, default=None, help="Maximum CISA KEV records to import.")
    parser.add_argument("--openssf-limit", type=int, default=None, help="Maximum OpenSSF MAL-* records to import.")
    parser.add_argument("--openssf-scan-limit", type=int, default=None, help="Maximum OSV JSON records to scan for MAL-* records.")
    parser.add_argument("--osv-dump-url", default=None, help="Override OSV dump URL.")
    parser.add_argument("--openssf-dump-url", default=None, help="Override OpenSSF source dump URL.")
    parser.add_argument("--cisa-catalog-url", default=None, help="Override CISA KEV catalog URL.")
    parser.add_argument("--osv-zip-path", type=Path, default=None, help="Read OSV bootstrap data from a local ZIP.")
    parser.add_argument("--openssf-zip-path", type=Path, default=None, help="Read OpenSSF bootstrap data from a local ZIP.")
    parser.add_argument("--cisa-json-path", type=Path, default=None, help="Read CISA KEV bootstrap data from a local JSON file.")
    parser.add_argument(
        "--skip-source",
        choices=("osv", "cisa_kev", "openssf"),
        action="append",
        default=[],
        help="Skip one bootstrap source. Can be repeated.",
    )
    parser.add_argument("--lock-owner-prefix", default="bootstrap-advisory-sync", help="Prefix for source sync lock owners.")
    parser.add_argument("--lock-ttl-seconds", type=int, default=3600, help="Source sync lock TTL.")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop after the first source error.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app = ScaMonitorApp(load_settings(component="worker"))
    result = run_bootstrap_advisory_sync(app, args)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ok":
        print("bootstrap advisory sync ok")
    else:
        print(f"bootstrap advisory sync blocked: {', '.join(result['blocking_sources'])}", file=sys.stderr)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
