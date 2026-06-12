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
from scripts.systemd_scheduler_status import build_status, default_unit_dir


def alert_channel_readiness(activation: dict[str, Any]) -> dict[str, Any]:
    channel = activation.get("preflight", {}).get("default_alert_channel", {})
    configured = bool(channel.get("configured"))
    placeholder = bool(channel.get("placeholder_target", True))
    return {
        "configured": configured,
        "ready": configured and not placeholder,
        "channel_type": channel.get("channel_type"),
        "target_url_masked": channel.get("target_url_masked"),
        "placeholder_target": placeholder,
    }


def build_go_live_gate(
    app: ScaMonitorApp,
    *,
    limit: int,
    unit_dir: Path | None,
    prefix: str,
    scope: str,
    include_systemctl: bool,
) -> dict[str, Any]:
    activation = run_alert_dispatcher_activation_check(app, limit=limit)
    systemd = build_status(unit_dir or default_unit_dir(scope), prefix, scope, include_systemctl)
    systemctl = systemd.get("systemctl", {})
    live_unit = f"{prefix}-alert-dispatcher.service"
    dry_run_unit = f"{prefix}-alert-dispatcher-dry-run.service"
    items = [
        {
            "name": "activation_check_ready",
            "status": "passed" if activation["status"] == "ready" else "failed",
            "blocking": True,
            "reason": "alert dispatcher activation checklist must be ready",
        },
        {
            "name": "systemd_units_valid",
            "status": "passed" if systemd["status"] == "ok" else "failed",
            "blocking": True,
            "reason": "all SCA Monitor systemd unit files must be present and valid",
        },
    ]
    if include_systemctl:
        dry_run_active = systemctl.get(dry_run_unit, {}).get("active") == "active"
        live_inactive = systemctl.get(live_unit, {}).get("active") in {"inactive", "failed", "unknown:exit-3"}
        items.extend(
            [
                {
                    "name": "dry_run_dispatcher_active",
                    "status": "passed" if dry_run_active else "failed",
                    "blocking": True,
                    "reason": "dry-run dispatcher should be active before switching to live dispatch",
                },
                {
                    "name": "live_dispatcher_not_active",
                    "status": "passed" if live_inactive else "failed",
                    "blocking": True,
                    "reason": "live dispatcher should not already be active during go-live gate review",
                },
            ]
        )
    blocking_failures = [item["name"] for item in items if item["blocking"] and item["status"] != "passed"]
    return {
        "status": "ready" if not blocking_failures else "blocked",
        "blocking_failures": blocking_failures,
        "items": items,
        "alert_channel_readiness": alert_channel_readiness(activation),
        "activation_check": activation,
        "systemd": systemd,
        "go_live_command": (
            "SCA_MONITOR_SYSTEMD_MODE=enable "
            f"SCA_MONITOR_SYSTEMD_SCOPE={scope} "
            f"SCA_MONITOR_SYSTEMD_PREFIX={prefix} "
            "scripts/deploy_remote.sh"
        ),
        "next_action": "enable_live_dispatcher" if not blocking_failures else "resolve_blocking_failures",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check all gates before enabling the live alert dispatcher.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum eligible alert rows to inspect via dry-run.")
    parser.add_argument("--prefix", default="sca-monitor", help="Systemd unit name prefix.")
    parser.add_argument("--user", dest="scope", action="store_const", const="user", default="user")
    parser.add_argument("--system", dest="scope", action="store_const", const="system")
    parser.add_argument("--unit-dir", type=Path, help="Unit directory to inspect. Defaults to the selected systemd scope.")
    parser.add_argument(
        "--skip-systemctl-state",
        action="store_true",
        help="Validate unit files without requiring active/inactive systemctl state.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app = ScaMonitorApp(load_settings())
    result = build_go_live_gate(
        app,
        limit=args.limit,
        unit_dir=args.unit_dir,
        prefix=args.prefix,
        scope=args.scope,
        include_systemctl=not args.skip_systemctl_state,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ready":
        print("alert dispatcher go-live ready")
    else:
        print(f"alert dispatcher go-live blocked: {', '.join(result['blocking_failures'])}", file=sys.stderr)
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
