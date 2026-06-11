#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge alias-related advisory rows into the canonical advisory row.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum alias groups to scan")
    parser.add_argument("--dry-run", action="store_true", help="Report merge candidates without updating rows")
    parser.add_argument("--actor", default="canonical-advisory-merge", help="Actor recorded in audit logs")
    parser.add_argument(
        "--skip-impact-backfill",
        action="store_true",
        help="Do not run canonical impact key backfill after advisory row merges",
    )
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    result = app.merge_canonical_advisory_rows(limit=args.limit, dry_run=args.dry_run, actor=args.actor)
    if not args.dry_run and not args.skip_impact_backfill:
        result["impact_backfill"] = app.backfill_canonical_impact_keys(limit=args.limit, dry_run=False, actor=args.actor)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
