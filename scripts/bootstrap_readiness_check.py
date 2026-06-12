#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.alert_preflight import run_alert_dispatcher_activation_check
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def build_bootstrap_readiness(
    app: ScaMonitorApp,
    *,
    alert_limit: int,
    include_alert_activation: bool,
    require_advisory_freshness: bool = False,
) -> dict[str, Any]:
    db_readiness = app.db.readiness()
    overview = app.overview()
    advisory_readiness = overview["advisory_sync_readiness"]
    items = [
        {
            "name": "database_ready",
            "status": "passed" if db_readiness["database"] == "ok" else "failed",
            "blocking": True,
            "reason": "database readiness and migration compatibility must be ok",
        },
        {
            "name": "advisory_initial_sync_ready",
            "status": "passed" if advisory_readiness["status"] == "ready" else "failed",
            "blocking": True,
            "reason": f"advisory sync readiness is {advisory_readiness['status']}",
        },
    ]
    if require_advisory_freshness:
        freshness_status = advisory_readiness["freshness"]["status"]
        items.append(
            {
                "name": "advisory_freshness_ready",
                "status": "passed" if freshness_status == "fresh" else "failed",
                "blocking": True,
                "reason": f"advisory sync freshness is {freshness_status}",
            }
        )
    result: dict[str, Any] = {
        "database": db_readiness,
        "advisory_sync_readiness": advisory_readiness,
    }
    if include_alert_activation:
        alert_activation = run_alert_dispatcher_activation_check(app, limit=alert_limit)
        result["alert_dispatcher_activation"] = alert_activation
        items.append(
            {
                "name": "alert_dispatcher_activation_ready",
                "status": "passed" if alert_activation["status"] == "ready" else "failed",
                "blocking": True,
                "reason": f"alert dispatcher activation is {alert_activation['status']}",
            }
        )

    blocking_failures = [item["name"] for item in items if item["blocking"] and item["status"] != "passed"]
    result.update(
        {
            "status": "ready" if not blocking_failures else "blocked",
            "blocking_failures": blocking_failures,
            "items": items,
            "next_action": "bootstrap_complete" if not blocking_failures else "resolve_blocking_failures",
        }
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check whether SCA Monitor bootstrap gates are ready.")
    parser.add_argument("--alert-limit", type=int, default=50, help="Maximum eligible alert rows to inspect via dispatcher dry-run.")
    parser.add_argument(
        "--skip-alert-activation",
        action="store_true",
        help="Check DB and advisory initial sync readiness without requiring a live alert target.",
    )
    parser.add_argument(
        "--require-advisory-freshness",
        action="store_true",
        help="Block when any required advisory source is stale, partial, failed, or pending.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app = ScaMonitorApp(load_settings())
    result = build_bootstrap_readiness(
        app,
        alert_limit=args.alert_limit,
        include_alert_activation=not args.skip_alert_activation,
        require_advisory_freshness=args.require_advisory_freshness,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ready":
        print("bootstrap readiness ok")
    else:
        print(f"bootstrap readiness blocked: {', '.join(result['blocking_failures'])}", file=sys.stderr)
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
