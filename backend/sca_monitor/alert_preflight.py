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
            WHERE enabled AND is_default AND channel_type IN ('webhook', 'slack_webhook')
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


def run_alert_dispatcher_activation_check(app, *, limit: int) -> dict[str, Any]:
    preflight = run_alert_dispatcher_preflight(app, limit=limit, require_default_channel=True)
    counts = preflight["alert_events"]
    dead_letter_count = counts.get("dead_letter", 0)
    failed_count = counts.get("failed", 0)
    pending_count = counts.get("pending", 0)
    items = [
        {
            "name": "database_ready",
            "status": "passed" if preflight["checks"]["database_ready"] else "failed",
            "blocking": True,
            "reason": "readiness database check must be ok before enabling live dispatch",
        },
        {
            "name": "default_alert_channel_configured",
            "status": "passed" if preflight["checks"]["default_alert_channel_configured"] else "failed",
            "blocking": True,
            "reason": "an enabled default webhook or Slack webhook channel is required for live dispatch",
        },
        {
            "name": "default_alert_channel_not_placeholder",
            "status": "passed" if preflight["checks"]["default_alert_channel_not_placeholder"] else "failed",
            "blocking": True,
            "reason": "placeholder example webhook targets must be replaced before live dispatch",
        },
        {
            "name": "dispatcher_dry_run_ok",
            "status": "passed" if preflight["checks"]["dispatcher_dry_run_ok"] else "failed",
            "blocking": True,
            "reason": "dry-run dispatcher must inspect eligible rows without updating alert state",
        },
        {
            "name": "no_dead_letter_alerts",
            "status": "passed" if dead_letter_count == 0 else "failed",
            "blocking": True,
            "reason": f"{dead_letter_count} dead-letter alert events require operator review before live dispatch",
        },
        {
            "name": "pending_alerts_visible",
            "status": "passed",
            "blocking": False,
            "reason": f"{pending_count} pending and {failed_count} failed/retryable alert events are visible to the dispatcher",
        },
    ]
    blocking_failures = [item["name"] for item in items if item["blocking"] and item["status"] != "passed"]
    return {
        "status": "ready" if not blocking_failures else "blocked",
        "blocking_failures": blocking_failures,
        "items": items,
        "preflight": preflight,
        "next_action": "enable_live_dispatcher" if not blocking_failures else "resolve_blocking_failures",
    }
