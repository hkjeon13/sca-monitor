#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import os

from backend.sca_monitor.config import load_settings
from backend.sca_monitor.db import Database


def main() -> None:
    settings = load_settings()
    database = Database(os.getenv("MIGRATION_DATABASE_URL") or settings.database_url)
    database.migrate()
    readiness = database.readiness()
    migration = readiness["migration"]
    print(
        "migration ok: "
        f"backend={readiness['database_backend']} "
        f"current={migration['current']} "
        f"required={migration['required']} "
        f"minimum_supported={migration['minimum_supported']}"
    )


if __name__ == "__main__":
    main()
