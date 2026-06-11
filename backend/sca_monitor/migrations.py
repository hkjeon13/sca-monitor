from __future__ import annotations

from pathlib import Path

REQUIRED_MIGRATION_VERSION = 5
MINIMUM_SUPPORTED_MIGRATION_VERSION = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "migrations"


def migration_files(backend: str) -> list[Path]:
    migration_dir = MIGRATIONS_DIR / backend
    if not migration_dir.exists():
        return []
    return sorted(migration_dir.glob("[0-9][0-9][0-9]_*.sql"))


def migration_version(path: Path) -> int:
    return int(path.name.split("_", 1)[0])
