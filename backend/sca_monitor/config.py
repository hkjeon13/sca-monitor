from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


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
    database_url_source: str = "default_sqlite"
    auth_mode: str = "disabled"
    auto_migrate: bool = True
    max_snapshot_payload_bytes: int = 10 * 1024 * 1024
    max_snapshot_dependencies: int = 10000
    max_snapshot_pushes_per_minute: int = 30
    strict_snapshot_push: bool = False
    advisory_sync_stale_after_seconds: int = 24 * 60 * 60


def load_settings(component: str = "api") -> Settings:
    data_dir = Path(os.getenv("SCA_MONITOR_DATA_DIR", ".data")).resolve()
    frontend_dir = Path(os.getenv("SCA_MONITOR_FRONTEND_DIR", "frontend")).resolve()
    legacy_database_path = Path(os.getenv("SCA_MONITOR_DB", str(data_dir / "sca-monitor.sqlite3"))).resolve()
    if component not in {"api", "worker"}:
        raise ValueError(f"unsupported settings component: {component}")
    component_database_url_name = "WORKER_DATABASE_URL" if component == "worker" else "API_DATABASE_URL"
    component_database_url = os.getenv(component_database_url_name)
    auto_migrate = env_flag(
        os.getenv(f"SCA_MONITOR_{component.upper()}_AUTO_MIGRATE")
        or os.getenv("SCA_MONITOR_AUTO_MIGRATE"),
        default=True,
    )
    database_url, database_url_source = resolve_database_url(
        component_database_url_name=component_database_url_name,
        component_database_url=component_database_url,
        legacy_database_path=legacy_database_path,
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
        database_url_source=database_url_source,
        auth_mode=os.getenv("SCA_MONITOR_AUTH_MODE", "disabled"),
        auto_migrate=auto_migrate,
        max_snapshot_payload_bytes=int(os.getenv("SCA_MONITOR_MAX_SNAPSHOT_PAYLOAD_BYTES", str(10 * 1024 * 1024))),
        max_snapshot_dependencies=int(os.getenv("SCA_MONITOR_MAX_SNAPSHOT_DEPENDENCIES", "10000")),
        max_snapshot_pushes_per_minute=int(os.getenv("SCA_MONITOR_MAX_SNAPSHOT_PUSHES_PER_MINUTE", "30")),
        strict_snapshot_push=env_flag(os.getenv("SCA_MONITOR_STRICT_SNAPSHOT_PUSH"), default=False),
        advisory_sync_stale_after_seconds=int(os.getenv("SCA_MONITOR_ADVISORY_SYNC_STALE_AFTER_SECONDS", str(24 * 60 * 60))),
    )


def resolve_database_url(*, component_database_url_name: str, component_database_url: str | None, legacy_database_path: Path) -> tuple[str, str]:
    shared_database_url = os.getenv("SCA_MONITOR_DATABASE_URL")
    api_database_url = os.getenv("API_DATABASE_URL")
    if shared_database_url:
        return shared_database_url, "SCA_MONITOR_DATABASE_URL"
    if component_database_url:
        return component_database_url, component_database_url_name
    if api_database_url:
        return api_database_url, "API_DATABASE_URL"
    return f"sqlite:///{legacy_database_path}", "SCA_MONITOR_DB" if os.getenv("SCA_MONITOR_DB") else "default_sqlite"


def database_backend_from_url(database_url: str) -> str:
    parsed = urlparse(database_url)
    if parsed.scheme in {"postgres", "postgresql"}:
        return "postgres"
    if parsed.scheme == "sqlite" or "://" not in database_url:
        return "sqlite"
    return parsed.scheme or "unknown"


def runtime_database_url_summary(settings: Settings) -> dict[str, dict[str, object]]:
    worker_url, worker_source = resolve_database_url(
        component_database_url_name="WORKER_DATABASE_URL",
        component_database_url=os.getenv("WORKER_DATABASE_URL"),
        legacy_database_path=settings.database_path,
    )
    migration_url = os.getenv("MIGRATION_DATABASE_URL") or settings.database_url
    migration_source = "MIGRATION_DATABASE_URL" if os.getenv("MIGRATION_DATABASE_URL") else settings.database_url_source
    roles = {
        "api": (settings.database_url, settings.database_url_source),
        "worker": (worker_url, worker_source),
        "migration": (migration_url, migration_source),
    }
    return {
        role: {
            "source": source,
            "backend": database_backend_from_url(database_url),
            "configured": source != "default_sqlite",
        }
        for role, (database_url, source) in roles.items()
    }


def runtime_auto_migrate_summary(env: dict[str, str] | None = None) -> dict[str, dict[str, object]]:
    env = os.environ if env is None else env

    def component_summary(component: str) -> dict[str, object]:
        component_name = f"SCA_MONITOR_{component.upper()}_AUTO_MIGRATE"
        if env.get(component_name, "") != "":
            source = component_name
            raw_value = env.get(component_name)
        elif env.get("SCA_MONITOR_AUTO_MIGRATE", "") != "":
            source = "SCA_MONITOR_AUTO_MIGRATE"
            raw_value = env.get("SCA_MONITOR_AUTO_MIGRATE")
        else:
            source = "default"
            raw_value = None
        try:
            return {"enabled": env_flag(raw_value, default=True), "source": source}
        except ValueError as exc:
            return {"enabled": True, "source": source, "error": str(exc)}

    return {
        "api": component_summary("api"),
        "worker": component_summary("worker"),
    }


def env_flag(value: str | None, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean environment value: {value}")
