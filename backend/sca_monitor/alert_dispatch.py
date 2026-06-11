from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4
from urllib.request import Request, urlopen

from .app import ScaMonitorApp
from .db import utcnow


@dataclass(frozen=True)
class AlertDispatchResult:
    pending: int
    claimed: int
    sent: int
    failed: int
    dry_run: bool


def dispatch_pending_alerts(
    app: ScaMonitorApp,
    *,
    webhook_url: str | None,
    limit: int = 50,
    dry_run: bool = False,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 300,
    retry_backoff_seconds: int = 300,
    sender: Callable[[str, dict], None] | None = None,
) -> AlertDispatchResult:
    now = utcnow()
    owner = lock_owner or default_lock_owner()
    webhook_url = webhook_url or app.default_alert_webhook_url()
    with app.db.connect() as conn:
        eligible_rows = conn.execute(
            """
            SELECT ae.*, i.risk_level, i.package_name, i.resolved_version,
                   s.service_id, s.service_name, s.environment,
                   a.advisory_id, a.summary
            FROM alert_events ae
            LEFT JOIN impacts i ON i.id = ae.impact_pk
            LEFT JOIN services s ON s.id = i.service_pk
            LEFT JOIN advisories a ON a.id = i.advisory_pk
            WHERE ae.status = 'pending'
               OR (ae.status = 'failed' AND (ae.next_attempt_at IS NULL OR ae.next_attempt_at <= ?))
               OR (ae.status = 'dispatching' AND (ae.dispatch_lock_expires_at IS NULL OR ae.dispatch_lock_expires_at <= ?))
            ORDER BY ae.created_at ASC
            LIMIT ?
            """,
            (now, now, limit),
        ).fetchall()

        if dry_run:
            return AlertDispatchResult(pending=len(eligible_rows), claimed=0, sent=0, failed=0, dry_run=True)
        if eligible_rows and not webhook_url:
            raise ValueError("webhook_url required when pending alerts exist")

        rows = []
        lock_expires_at = utcnow_after_seconds(lock_ttl_seconds)
        for row in eligible_rows:
            updated = conn.execute(
                """
                UPDATE alert_events
                SET status = 'dispatching', dispatch_lock_owner = ?, dispatch_lock_expires_at = ?
                WHERE id = ?
                  AND (
                    status = 'pending'
                    OR (status = 'failed' AND (next_attempt_at IS NULL OR next_attempt_at <= ?))
                    OR (status = 'dispatching' AND (dispatch_lock_expires_at IS NULL OR dispatch_lock_expires_at <= ?))
                  )
                """,
                (owner, lock_expires_at, row["id"], now, now),
            ).rowcount
            if updated == 1:
                rows.append(row)

        send = sender or send_webhook
        sent = 0
        failed = 0
        for row in rows:
            payload = alert_payload(row)
            try:
                send(webhook_url or "", payload)
            except Exception as exc:
                failed += 1
                next_attempt_at = utcnow_after_seconds(retry_delay_seconds(row["retry_count"], retry_backoff_seconds))
                conn.execute(
                    """
                    UPDATE alert_events
                    SET status = 'failed', payload = ?, retry_count = retry_count + 1,
                        next_attempt_at = ?, dispatch_lock_owner = NULL, dispatch_lock_expires_at = NULL
                    WHERE id = ?
                    """,
                    (json.dumps({**payload, "dispatch_error": str(exc)}, ensure_ascii=False), next_attempt_at, row["id"]),
                )
                continue
            sent += 1
            conn.execute(
                """
                UPDATE alert_events
                SET status = 'sent', sent_at = ?, channel_type = 'webhook',
                    channel_target = ?, payload = ?, dispatch_lock_owner = NULL,
                    dispatch_lock_expires_at = NULL, next_attempt_at = NULL
                WHERE id = ?
                """,
                (utcnow(), webhook_url, json.dumps(payload, ensure_ascii=False), row["id"]),
            )
    return AlertDispatchResult(pending=len(eligible_rows), claimed=len(rows), sent=sent, failed=failed, dry_run=False)


def dispatch_alert_batches(
    app: ScaMonitorApp,
    *,
    webhook_url: str | None,
    limit: int = 50,
    dry_run: bool = False,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 300,
    retry_backoff_seconds: int = 300,
    iterations: int = 1,
    interval_seconds: float = 0,
    sender: Callable[[str, dict], None] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> list[AlertDispatchResult]:
    if iterations < 0:
        raise ValueError("iterations must be 0 or greater")
    results = []
    sleep = sleeper or time.sleep
    iteration = 0
    while iterations == 0 or iteration < iterations:
        iteration += 1
        result = dispatch_pending_alerts(
            app,
            webhook_url=webhook_url,
            limit=limit,
            dry_run=dry_run,
            lock_owner=lock_owner,
            lock_ttl_seconds=lock_ttl_seconds,
            retry_backoff_seconds=retry_backoff_seconds,
            sender=sender,
        )
        results.append(result)
        if iterations != 0 and iteration >= iterations:
            break
        if interval_seconds > 0:
            sleep(interval_seconds)
    return results


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


def retry_delay_seconds(retry_count: int, base_seconds: int) -> int:
    return max(1, base_seconds) * (2 ** min(retry_count, 5))


def utcnow_after_seconds(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def default_lock_owner() -> str:
    return f"alert-dispatch:{socket.gethostname()}:{uuid4()}"
