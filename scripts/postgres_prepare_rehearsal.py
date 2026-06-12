#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.cutover_readiness_report import report, write_report
from scripts.database_env_dry_run_gate import BASE_RUNTIME_ENV
from scripts.prepare_database_env_file import DEFAULT_TEMPLATE, prepare


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rehearse PostgreSQL env preparation and expected-blocked cutover reporting in a temporary workspace."
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def file_mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def run_rehearsal() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sca-monitor-postgres-prepare-rehearsal-") as tmp:
        tmp_path = Path(tmp)
        runtime_env_file = tmp_path / ".env"
        database_env_file = tmp_path / "postgres.env"
        report_path = tmp_path / "cutover-readiness-report.json"

        runtime_env_file.write_text(BASE_RUNTIME_ENV, encoding="utf-8")
        runtime_env_file.chmod(0o600)
        prepare_result = prepare(database_env_file, DEFAULT_TEMPLATE, force=False)
        cutover_report = report(
            env_file=runtime_env_file,
            database_env_file=database_env_file,
            backup_path=None,
            require_postgres=True,
            require_split=True,
            require_runtime_inputs=True,
            run_live_preflight=False,
        )
        cutover_report["expected_status"] = "blocked"
        cutover_report["expectation_met"] = cutover_report["status"] == "blocked"
        write_report(report_path, cutover_report)

        return {
            "status": cutover_report["status"],
            "mode": "temporary",
            "database_env_file": "temporary",
            "database_env_file_mode": file_mode(database_env_file),
            "cutover_report_path": "temporary",
            "cutover_report_mode": file_mode(report_path),
            "prepare": {
                "status": prepare_result["status"],
                "validator_status": (prepare_result.get("validator") or {}).get("status"),
            },
            "cutover_report": {
                "status": cutover_report["status"],
                "expected_status": cutover_report["expected_status"],
                "expectation_met": cutover_report["expectation_met"],
                "summary": cutover_report["summary"],
                "inputs": cutover_report["inputs"],
            },
        }


def main() -> int:
    args = parse_args()
    result = run_rehearsal()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"postgres prepare rehearsal: {result['status']}")
        print(f"- prepare: {result['prepare']['status']} validator={result['prepare']['validator_status']}")
        print(
            "- cutover report: "
            f"expected={result['cutover_report']['expected_status']} "
            f"met={result['cutover_report']['expectation_met']}"
        )
    return 0 if result["cutover_report"]["expectation_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
