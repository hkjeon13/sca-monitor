from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_env: str
    host: str
    port: int
    data_dir: Path
    database_url: str
    database_path: Path
    frontend_dir: Path
    smoke_token: str
    auth_mode: str = "disabled"
    max_snapshot_payload_bytes: int = 10 * 1024 * 1024
    max_snapshot_dependencies: int = 10000
    max_snapshot_pushes_per_minute: int = 30


def load_settings() -> Settings:
    data_dir = Path(os.getenv("SCA_MONITOR_DATA_DIR", ".data")).resolve()
    frontend_dir = Path(os.getenv("SCA_MONITOR_FRONTEND_DIR", "frontend")).resolve()
    legacy_database_path = Path(os.getenv("SCA_MONITOR_DB", str(data_dir / "sca-monitor.sqlite3"))).resolve()
    database_url = (
        os.getenv("SCA_MONITOR_DATABASE_URL")
        or os.getenv("API_DATABASE_URL")
        or f"sqlite:///{legacy_database_path}"
    )
    return Settings(
        app_env=os.getenv("APP_ENV", "dev"),
        host=os.getenv("SCA_MONITOR_HOST", "127.0.0.1"),
        port=int(os.getenv("SCA_MONITOR_PORT", "18780")),
        data_dir=data_dir,
        database_url=database_url,
        database_path=legacy_database_path,
        frontend_dir=frontend_dir,
        smoke_token=os.getenv("SMOKE_TEST_TOKEN", "dev-smoke-token"),
        auth_mode=os.getenv("SCA_MONITOR_AUTH_MODE", "disabled"),
        max_snapshot_payload_bytes=int(os.getenv("SCA_MONITOR_MAX_SNAPSHOT_PAYLOAD_BYTES", str(10 * 1024 * 1024))),
        max_snapshot_dependencies=int(os.getenv("SCA_MONITOR_MAX_SNAPSHOT_DEPENDENCIES", "10000")),
        max_snapshot_pushes_per_minute=int(os.getenv("SCA_MONITOR_MAX_SNAPSHOT_PUSHES_PER_MINUTE", "30")),
    )
