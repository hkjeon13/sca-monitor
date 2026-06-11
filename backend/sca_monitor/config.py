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
    database_path: Path
    frontend_dir: Path
    smoke_token: str


def load_settings() -> Settings:
    data_dir = Path(os.getenv("SCA_MONITOR_DATA_DIR", ".data")).resolve()
    frontend_dir = Path(os.getenv("SCA_MONITOR_FRONTEND_DIR", "frontend")).resolve()
    return Settings(
        app_env=os.getenv("APP_ENV", "dev"),
        host=os.getenv("SCA_MONITOR_HOST", "127.0.0.1"),
        port=int(os.getenv("SCA_MONITOR_PORT", "18780")),
        data_dir=data_dir,
        database_path=Path(os.getenv("SCA_MONITOR_DB", str(data_dir / "sca-monitor.sqlite3"))).resolve(),
        frontend_dir=frontend_dir,
        smoke_token=os.getenv("SMOKE_TEST_TOKEN", "dev-smoke-token"),
    )

