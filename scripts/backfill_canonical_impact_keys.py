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
    parser = argparse.ArgumentParser(description="Backfill impact identity and alert suppression keys to canonical advisory keys.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum impact rows to scan")
    parser.add_argument("--dry-run", action="store_true", help="Report candidate changes without updating rows")
    parser.add_argument("--actor", default="canonical-backfill", help="Actor recorded in impact history")
    args = parser.parse_args()

    app = ScaMonitorApp(load_settings(component="worker"))
    result = app.backfill_canonical_impact_keys(limit=args.limit, dry_run=args.dry_run, actor=args.actor)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
