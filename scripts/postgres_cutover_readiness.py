#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.sca_monitor.postgres_cutover import assess_cutover


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assess PostgreSQL cutover environment readiness before deployment.")
    parser.add_argument("--require-postgres", action="store_true", help="Fail unless configured DB URLs are PostgreSQL-ready.")
    parser.add_argument("--require-split", action="store_true", help="Fail unless migration/API/worker split credentials are used.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = assess_cutover(os.environ, require_postgres=args.require_postgres, require_split=args.require_split)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"postgres cutover readiness: {result['status']} ({result['mode']})")
        for check in result["checks"]:
            print(f"- {check['status']}: {check['id']}: {check['detail']}")
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
