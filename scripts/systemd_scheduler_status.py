#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_UNITS = {
    "api.service": {
        "required": ["ExecStart=", "-m backend.sca_monitor"],
        "kind": "service",
    },
    "endpoint-poller.service": {
        "required": ["scripts/poll_endpoints.py", "--iterations 0", "--lock-owner systemd-endpoint-poller"],
        "kind": "service",
    },
    "alert-dispatcher.service": {
        "required": ["scripts/dispatch_alerts.py", "--iterations 0", "--lock-owner systemd-alert-dispatcher"],
        "kind": "service",
    },
    "alert-dispatcher-dry-run.service": {
        "required": [
            "scripts/dispatch_alerts.py",
            "--iterations 0",
            "--lock-owner systemd-alert-dispatcher-dry-run",
            "--dry-run",
        ],
        "kind": "service",
    },
    "accepted-risk-expiry.service": {
        "required": ["scripts/expire_accepted_risks.py", "--actor risk-scheduler"],
        "kind": "oneshot",
    },
    "accepted-risk-expiry.timer": {
        "required": ["OnUnitActiveSec=15min", "Unit={prefix}-accepted-risk-expiry.service"],
        "kind": "timer",
    },
    "cisa-kev-sync.service": {
        "required": ["scripts/cisa_kev_sync.py", "--lock-owner systemd-cisa-kev-sync"],
        "kind": "oneshot",
    },
    "cisa-kev-sync.timer": {
        "required": ["OnUnitActiveSec=1h", "Unit={prefix}-cisa-kev-sync.service"],
        "kind": "timer",
    },
    "osv-npm-sync.service": {
        "required": ["scripts/osv_sync.py", "--ecosystem npm", "--lock-owner systemd-osv-npm-sync"],
        "kind": "oneshot",
    },
    "osv-npm-sync.timer": {
        "required": ["OnUnitActiveSec=1h", "Unit={prefix}-osv-npm-sync.service"],
        "kind": "timer",
    },
    "openssf-malicious-sync.service": {
        "required": [
            "scripts/osv_sync.py",
            "--source OpenSSF",
            "--malicious-only",
            "--lock-owner systemd-openssf-malicious-sync",
        ],
        "kind": "oneshot",
    },
    "openssf-malicious-sync.timer": {
        "required": ["OnUnitActiveSec=1h", "Unit={prefix}-openssf-malicious-sync.service"],
        "kind": "timer",
    },
}


def default_unit_dir(scope: str) -> Path:
    if scope == "system":
        return Path("/etc/systemd/system")
    return Path.home() / ".config" / "systemd" / "user"


def check_unit_files(unit_dir: Path, prefix: str) -> dict[str, Any]:
    units: dict[str, Any] = {}
    for suffix, spec in EXPECTED_UNITS.items():
        unit_name = f"{prefix}-{suffix}"
        path = unit_dir / unit_name
        unit_result: dict[str, Any] = {
            "path": str(path),
            "kind": spec["kind"],
            "exists": path.exists(),
            "valid": False,
            "missing_fragments": [],
        }
        if path.exists():
            text = path.read_text(encoding="utf-8")
            required = [fragment.format(prefix=prefix) for fragment in spec["required"]]
            missing = [fragment for fragment in required if fragment not in text]
            unit_result["missing_fragments"] = missing
            unit_result["valid"] = not missing
        units[unit_name] = unit_result
    return units


def systemctl_value(scope: str, unit: str, verb: str) -> str:
    command = ["systemctl"]
    if scope == "user":
        command.append("--user")
    command.extend([verb, unit])
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unknown:{exc.__class__.__name__}"
    value = (result.stdout or result.stderr).strip().splitlines()
    return value[0] if value else f"unknown:exit-{result.returncode}"


def collect_systemctl_status(scope: str, units: dict[str, Any]) -> dict[str, dict[str, str]]:
    status: dict[str, dict[str, str]] = {}
    for unit in units:
        status[unit] = {
            "enabled": systemctl_value(scope, unit, "is-enabled"),
            "active": systemctl_value(scope, unit, "is-active"),
        }
    return status


def build_status(unit_dir: Path, prefix: str, scope: str, include_systemctl: bool) -> dict[str, Any]:
    units = check_unit_files(unit_dir, prefix)
    missing = [unit for unit, data in units.items() if not data["exists"]]
    invalid = [unit for unit, data in units.items() if data["exists"] and not data["valid"]]
    result: dict[str, Any] = {
        "status": "ok" if not missing and not invalid else "not_ready",
        "scope": scope,
        "unit_dir": str(unit_dir),
        "prefix": prefix,
        "summary": {
            "expected": len(units),
            "present": len(units) - len(missing),
            "valid": len(units) - len(missing) - len(invalid),
            "missing": len(missing),
            "invalid": len(invalid),
        },
        "units": units,
    }
    if include_systemctl:
        result["systemctl"] = collect_systemctl_status(scope, units)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only status check for SCA Monitor systemd scheduler units.")
    parser.add_argument("--prefix", default="sca-monitor", help="Unit name prefix.")
    parser.add_argument("--user", dest="scope", action="store_const", const="user", default="user")
    parser.add_argument("--system", dest="scope", action="store_const", const="system")
    parser.add_argument("--unit-dir", type=Path, help="Unit directory to inspect.")
    parser.add_argument("--systemctl", action="store_true", help="Also query systemctl is-enabled/is-active.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    unit_dir = args.unit_dir or default_unit_dir(args.scope)
    result = build_status(unit_dir, args.prefix, args.scope, args.systemctl)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["status"] == "ok":
        print(
            "systemd scheduler ok: "
            f"scope={result['scope']} unit_dir={result['unit_dir']} "
            f"valid={result['summary']['valid']}/{result['summary']['expected']}"
        )
    else:
        print(
            "systemd scheduler not ready: "
            f"scope={result['scope']} unit_dir={result['unit_dir']} "
            f"missing={result['summary']['missing']} invalid={result['summary']['invalid']}",
            file=sys.stderr,
        )
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
