from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable
from urllib.request import Request, urlopen

from .app import ScaMonitorApp
from .db import utcnow


@dataclass(frozen=True)
class AlertDispatchResult:
    pending: int
    sent: int
    failed: int
    dry_run: bool


def dispatch_pending_alerts(
    app: ScaMonitorApp,
    *,
    webhook_url: str | None,
    limit: int = 50,
    dry_run: bool = False,
    sender: Callable[[str, dict], None] | None = None,
) -> AlertDispatchResult:
    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT ae.*, i.risk_level, i.package_name, i.resolved_version,
                   s.service_id, s.service_name, s.environment,
                   a.advisory_id, a.summary
            FROM alert_events ae
            LEFT JOIN impacts i ON i.id = ae.impact_pk
            LEFT JOIN services s ON s.id = i.service_pk
            LEFT JOIN advisories a ON a.id = i.advisory_pk
            WHERE ae.status = 'pending'
            ORDER BY ae.created_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        if dry_run:
            return AlertDispatchResult(pending=len(rows), sent=0, failed=0, dry_run=True)
        if rows and not webhook_url:
            raise ValueError("webhook_url required when pending alerts exist")

        send = sender or send_webhook
        sent = 0
        failed = 0
        for row in rows:
            payload = alert_payload(row)
            try:
                send(webhook_url or "", payload)
            except Exception as exc:
                failed += 1
                conn.execute(
                    """
                    UPDATE alert_events
                    SET status = 'failed', payload = ?, created_at = created_at
                    WHERE id = ?
                    """,
                    (json.dumps({**payload, "dispatch_error": str(exc)}, ensure_ascii=False), row["id"]),
                )
                continue
            sent += 1
            conn.execute(
                """
                UPDATE alert_events
                SET status = 'sent', sent_at = ?, channel_type = 'webhook',
                    channel_target = ?, payload = ?
                WHERE id = ?
                """,
                (utcnow(), webhook_url, json.dumps(payload, ensure_ascii=False), row["id"]),
            )
    return AlertDispatchResult(pending=len(rows), sent=sent, failed=failed, dry_run=False)


def alert_payload(row) -> dict:
    base_payload = json.loads(row["payload"] or "{}")
    return {
        **base_payload,
        "alert_event_id": row["id"],
        "impact_id": row["impact_pk"],
        "alert_suppression_key": row["alert_suppression_key"],
        "reason": row["reason"],
        "service_id": row["service_id"],
        "service_name": row["service_name"],
        "environment": row["environment"],
        "advisory_id": row["advisory_id"],
        "summary": row["summary"],
        "risk_level": row["risk_level"],
        "package_name": row["package_name"],
        "resolved_version": row["resolved_version"],
    }


def send_webhook(webhook_url: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "sca-monitor/0.1"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        if response.status >= 400:
            raise RuntimeError(f"webhook returned HTTP {response.status}")
