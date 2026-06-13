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

from backend.sca_monitor.migrations import REQUIRED_MIGRATION_VERSION, migration_files, migration_version


BACKENDS = ("sqlite", "postgres")


def backend_manifest(backend: str) -> dict[str, Any]:
    versions = [migration_version(path) for path in migration_files(backend)]
    duplicate_versions = sorted({version for version in versions if versions.count(version) > 1})
    return {
        "count": len(versions),
        "latest": max(versions, default=0),
        "versions": versions,
        "duplicate_versions": duplicate_versions,
        "sequential": versions == list(range(1, max(versions, default=0) + 1)),
    }


def manifest_check() -> dict[str, Any]:
    backends = {backend: backend_manifest(backend) for backend in BACKENDS}
    sqlite_versions = set(backends["sqlite"]["versions"])
    postgres_versions = set(backends["postgres"]["versions"])
    latest = max((backend["latest"] for backend in backends.values()), default=0)
    required_matches_latest = REQUIRED_MIGRATION_VERSION == latest

    backend_alignment = {
        "matching_versions": sqlite_versions == postgres_versions,
        "missing_from_sqlite": sorted(postgres_versions - sqlite_versions),
        "missing_from_postgres": sorted(sqlite_versions - postgres_versions),
    }
    blockers: list[str] = []
    if not required_matches_latest:
        blockers.append("REQUIRED_MIGRATION_VERSION does not match latest migration file")
    for backend, manifest in backends.items():
        if manifest["duplicate_versions"]:
            blockers.append(f"{backend} migration versions contain duplicates")
        if not manifest["sequential"]:
            blockers.append(f"{backend} migration versions are not sequential")
    if not backend_alignment["matching_versions"]:
        blockers.append("sqlite and postgres migration version sets differ")

    return {
        "status": "ok" if not blockers else "blocked",
        "required_version": {
            "configured": REQUIRED_MIGRATION_VERSION,
            "latest": latest,
            "matches_latest": required_matches_latest,
        },
        "backends": backends,
        "backend_alignment": backend_alignment,
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate repository migration manifest consistency.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    result = manifest_check()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "migration manifest: "
            f"{result['status']} "
            f"required={result['required_version']['configured']} "
            f"latest={result['required_version']['latest']}"
        )
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
