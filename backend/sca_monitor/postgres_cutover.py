from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import env_flag


POSTGRES_PREFIXES = ("postgres://", "postgresql://")
VALID_SMOKE_MODES = {"auto", "required", "disabled", "skip", "false", "0", ""}


@dataclass(frozen=True)
class CutoverCheck:
    id: str
    status: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "status": self.status, "detail": self.detail}


def is_postgres_url(value: str | None) -> bool:
    return bool(value and value.startswith(POSTGRES_PREFIXES))


def is_set(value: str | None) -> bool:
    return value is not None and value.strip() != ""


def bool_env(env: dict[str, str], name: str, *, default: bool) -> tuple[bool | None, str | None]:
    try:
        return env_flag(env.get(name), default=default), None
    except ValueError as exc:
        return None, str(exc)


def runtime_auto_migrate_disabled(env: dict[str, str], component: str) -> tuple[bool, str | None]:
    component_name = f"SCA_MONITOR_{component.upper()}_AUTO_MIGRATE"
    if is_set(env.get(component_name)):
        value, error = bool_env(env, component_name, default=True)
        return value is False, error
    value, error = bool_env(env, "SCA_MONITOR_AUTO_MIGRATE", default=True)
    return value is False, error


def assess_cutover(env: dict[str, str], *, require_postgres: bool = False, require_split: bool = False) -> dict[str, Any]:
    shared_url = env.get("SCA_MONITOR_DATABASE_URL", "")
    migration_url = env.get("MIGRATION_DATABASE_URL", "")
    api_url = env.get("API_DATABASE_URL", "")
    worker_url = env.get("WORKER_DATABASE_URL", "")
    smoke_mode = env.get("SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE", "auto")
    checks: list[CutoverCheck] = []

    shared_configured = is_set(shared_url)
    split_configured = any(is_set(value) for value in (migration_url, api_url, worker_url))
    postgres_configured = any(is_postgres_url(value) for value in (shared_url, migration_url, api_url, worker_url))

    if smoke_mode not in VALID_SMOKE_MODES:
        checks.append(CutoverCheck("postgres_smoke_mode", "blocker", f"invalid SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE: {smoke_mode}"))
    elif require_postgres and smoke_mode in {"disabled", "skip", "false", "0"}:
        checks.append(CutoverCheck("postgres_smoke_mode", "blocker", "PostgreSQL cutover requires integration smoke to be auto or required"))
    else:
        checks.append(CutoverCheck("postgres_smoke_mode", "ok", f"SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE={smoke_mode or 'auto'}"))

    for name in ("SCA_MONITOR_AUTO_MIGRATE", "SCA_MONITOR_API_AUTO_MIGRATE", "SCA_MONITOR_WORKER_AUTO_MIGRATE"):
        if is_set(env.get(name)):
            _, error = bool_env(env, name, default=True)
            if error:
                checks.append(CutoverCheck("runtime_auto_migrate_flag", "blocker", f"{name}: {error}"))

    if shared_configured:
        if require_split:
            checks.append(CutoverCheck("database_url_mode", "blocker", "SCA_MONITOR_DATABASE_URL must be empty for split credential cutover"))
        elif split_configured:
            checks.append(CutoverCheck("database_url_mode", "warning", "SCA_MONITOR_DATABASE_URL overrides MIGRATION/API/WORKER_DATABASE_URL"))
        else:
            checks.append(CutoverCheck("database_url_mode", "ok", "shared database URL mode"))
        if require_postgres and not is_postgres_url(shared_url):
            checks.append(CutoverCheck("shared_database_url", "blocker", "SCA_MONITOR_DATABASE_URL is not PostgreSQL"))
        elif is_postgres_url(shared_url):
            checks.append(CutoverCheck("shared_database_url", "ok", "SCA_MONITOR_DATABASE_URL is PostgreSQL"))
    elif split_configured:
        checks.append(CutoverCheck("database_url_mode", "ok", "split credential database URL mode"))
        required_urls = {
            "MIGRATION_DATABASE_URL": migration_url,
            "API_DATABASE_URL": api_url,
            "WORKER_DATABASE_URL": worker_url,
        }
        for name, value in required_urls.items():
            if not is_set(value):
                status = "blocker" if require_postgres or require_split else "warning"
                checks.append(CutoverCheck(name.lower(), status, f"{name} is not configured"))
            elif require_postgres and not is_postgres_url(value):
                checks.append(CutoverCheck(name.lower(), "blocker", f"{name} is not PostgreSQL"))
            elif is_postgres_url(value):
                checks.append(CutoverCheck(name.lower(), "ok", f"{name} is PostgreSQL"))
            else:
                checks.append(CutoverCheck(name.lower(), "warning", f"{name} is not PostgreSQL"))

        for component in ("api", "worker"):
            disabled, error = runtime_auto_migrate_disabled(env, component)
            if error:
                continue
            if require_postgres and not disabled:
                checks.append(
                    CutoverCheck(
                        f"{component}_runtime_auto_migrate",
                        "blocker",
                        f"SCA_MONITOR_{component.upper()}_AUTO_MIGRATE or SCA_MONITOR_AUTO_MIGRATE must be false",
                    )
                )
            elif disabled:
                checks.append(CutoverCheck(f"{component}_runtime_auto_migrate", "ok", f"{component} runtime auto-migrate disabled"))
            else:
                checks.append(CutoverCheck(f"{component}_runtime_auto_migrate", "warning", f"{component} runtime auto-migrate is enabled"))
    else:
        status = "blocker" if require_postgres else "ok"
        detail = "no PostgreSQL database URL configured" if require_postgres else "SQLite fallback mode"
        checks.append(CutoverCheck("database_url_mode", status, detail))

    blockers = [check for check in checks if check.status == "blocker"]
    warnings = [check for check in checks if check.status == "warning"]
    if blockers:
        status = "blocked"
    elif require_postgres or postgres_configured:
        status = "ready"
    elif warnings:
        status = "action_required"
    else:
        status = "sqlite_fallback"

    return {
        "status": status,
        "mode": "shared" if shared_configured else "split" if split_configured else "sqlite_fallback",
        "require_postgres": require_postgres,
        "require_split": require_split,
        "postgres_configured": postgres_configured,
        "checks": [check.as_dict() for check in checks],
    }
