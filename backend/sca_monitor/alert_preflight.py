from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .alert_dispatch import dispatch_pending_alerts


def alert_event_counts(app) -> dict[str, int]:
    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM alert_events
            GROUP BY status
            ORDER BY status
            """
        ).fetchall()
    return {row["status"]: int(row["count"]) for row in rows}


def default_channel_summary(app) -> dict[str, Any]:
    with app.db.connect() as conn:
        row = conn.execute(
            """
            SELECT id, name, channel_type, target_url, enabled, is_default, updated_at
            FROM alert_channels
            WHERE enabled = 1 AND is_default = 1 AND channel_type = 'webhook'
            ORDER BY updated_at DESC
            LIMIT 1
            """
        ).fetchone()
    if not row:
        return {"configured": False}
    return {
        "configured": True,
        "id": row["id"],
        "name": row["name"],
        "channel_type": row["channel_type"],
        "target_url_masked": mask_url(row["target_url"]),
        "placeholder_target": is_placeholder_url(row["target_url"]),
    }


def is_placeholder_url(value: str | None) -> bool:
    if not value:
        return True
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if not host:
        return True
    return host in {"example.com", "example.net", "example.org", "example.test"} or host.endswith(".example.test")


def mask_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(value)
    if not parsed.netloc:
        return "***"
    return f"{parsed.scheme}://{parsed.netloc}/..."


def run_alert_dispatcher_preflight(app, *, limit: int, require_default_channel: bool = True) -> dict[str, Any]:
    readiness = app.db.readiness()
    channel = default_channel_summary(app)
    dry_run = dispatch_pending_alerts(app, webhook_url=None, limit=limit, dry_run=True)
    counts = alert_event_counts(app)
    checks = {
        "database_ready": readiness["database"] == "ok",
        "default_alert_channel_configured": bool(channel["configured"]),
        "default_alert_channel_not_placeholder": bool(channel["configured"]) and not channel.get("placeholder_target", True),
        "dispatcher_dry_run_ok": True,
    }
    if not require_default_channel:
        checks["default_alert_channel_configured"] = True
        checks["default_alert_channel_not_placeholder"] = True
    status = "ok" if all(checks.values()) else "failed"
    result = {
        "status": status,
        "checks": checks,
        "database": readiness,
        "default_alert_channel": channel,
        "dry_run": dry_run.__dict__,
        "alert_events": counts,
    }
    if status != "ok":
        failures = [name for name, passed in checks.items() if not passed]
        result["failures"] = failures
    return result
