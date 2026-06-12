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
from .db import json_column, utcnow


@dataclass(frozen=True)
class AlertDispatchResult:
    pending: int
    claimed: int
    sent: int
    failed: int
    dry_run: bool


@dataclass(frozen=True)
class AlertTarget:
    target_url: str
    channel_type: str


def dispatch_pending_alerts(
    app: ScaMonitorApp,
    *,
    webhook_url: str | None,
    limit: int = 50,
    dry_run: bool = False,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 300,
    retry_backoff_seconds: int = 300,
    max_retries: int = 5,
    sender: Callable | None = None,
) -> AlertDispatchResult:
    now = utcnow()
    owner = lock_owner or default_lock_owner()
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
        default_target = None if webhook_url else app.default_alert_channel_target()
        target_by_event_id = {
            row["id"]: resolve_alert_target(conn, row, explicit_webhook_url=webhook_url, default_target=default_target)
            for row in eligible_rows
        }
        if eligible_rows and any(target is None for target in target_by_event_id.values()):
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
            headers = alert_headers(row)
            target = target_by_event_id[row["id"]]
            try:
                call_sender(send, target.target_url, format_alert_for_channel(payload, target.channel_type), headers)
            except Exception as exc:
                failed += 1
                retry_count = int(row["retry_count"] or 0) + 1
                terminal = retry_count >= max_retries
                next_attempt_at = None if terminal else utcnow_after_seconds(retry_delay_seconds(row["retry_count"], retry_backoff_seconds))
                status = "dead_letter" if terminal else "failed"
                conn.execute(
                    """
                    UPDATE alert_events
                    SET status = ?, payload = ?, retry_count = ?,
                        next_attempt_at = ?, dispatch_lock_owner = NULL, dispatch_lock_expires_at = NULL
                    WHERE id = ?
                    """,
                    (
                        status,
                        json.dumps({**payload, "dispatch_error": str(exc), "dispatch_terminal": terminal}, ensure_ascii=False),
                        retry_count,
                        next_attempt_at,
                        row["id"],
                    ),
                )
                continue
            sent += 1
            conn.execute(
                """
                UPDATE alert_events
                SET status = 'sent', sent_at = ?, channel_type = ?,
                    channel_target = ?, payload = ?, dispatch_lock_owner = NULL,
                    dispatch_lock_expires_at = NULL, next_attempt_at = NULL
                WHERE id = ?
                """,
                (
                    utcnow(),
                    target.channel_type,
                    target.target_url,
                    json.dumps(format_alert_for_channel(payload, target.channel_type), ensure_ascii=False),
                    row["id"],
                ),
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
    max_retries: int = 5,
    sender: Callable | None = None,
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
            max_retries=max_retries,
            sender=sender,
        )
        results.append(result)
        if iterations != 0 and iteration >= iterations:
            break
        if interval_seconds > 0:
            sleep(interval_seconds)
    return results


def alert_payload(row) -> dict:
    base_payload = json_column(row["payload"], {})
    payload = {
        "alert_event_id": row["id"],
        "impact_id": row["impact_pk"],
        "alert_suppression_key": row["alert_suppression_key"],
        "reason": row["reason"],
    }
    for key in ("service_id", "service_name", "environment", "advisory_id", "summary", "risk_level", "package_name", "resolved_version"):
        value = row[key]
        if value is not None:
            payload[key] = value
    return {**base_payload, **payload}


def alert_headers(row) -> dict[str, str]:
    return {
        "Idempotency-Key": row["id"],
        "X-SCA-Alert-Event-Id": row["id"],
        "X-SCA-Alert-Suppression-Key": row["alert_suppression_key"],
    }


def resolve_alert_target(conn, row, *, explicit_webhook_url: str | None, default_target: dict | None) -> AlertTarget | None:
    if explicit_webhook_url:
        return AlertTarget(target_url=explicit_webhook_url, channel_type="webhook")
    owner_team = alert_owner_team(row)
    if owner_team:
        channel = conn.execute(
            """
            SELECT target_url, channel_type
            FROM alert_channels
            WHERE enabled AND channel_type IN ('webhook', 'slack_webhook') AND owner_team = ?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (owner_team,),
        ).fetchone()
        if channel and channel["target_url"]:
            return AlertTarget(target_url=channel["target_url"], channel_type=channel["channel_type"])
    if default_target:
        return AlertTarget(target_url=default_target["target_url"], channel_type=default_target["channel_type"])
    return None


def alert_owner_team(row) -> str | None:
    payload = json_column(row["payload"], {})
    digest = payload.get("digest") if isinstance(payload, dict) else None
    if isinstance(digest, dict) and digest.get("owner_team"):
        return str(digest["owner_team"])
    return None


def call_sender(sender: Callable, webhook_url: str, payload: dict, headers: dict[str, str]) -> None:
    try:
        sender(webhook_url, payload, headers)
    except TypeError as exc:
        try:
            sender(webhook_url, payload)
        except TypeError:
            raise exc


def format_alert_for_channel(payload: dict, channel_type: str) -> dict:
    if channel_type == "slack_webhook":
        return slack_webhook_payload(payload)
    return payload


def slack_webhook_payload(payload: dict) -> dict:
    if payload.get("reason") == "daily_digest" and isinstance(payload.get("digest"), dict):
        digest = payload["digest"]
        owner_team = digest.get("owner_team") or "all"
        matched = digest.get("matched")
        if matched is None:
            matched = len(payload.get("items") or [])
        title = f"[Daily Digest] {owner_team} - {matched} impacts"
        detail = f"*Date:* {digest.get('date', '-')}\n*Scope:* {owner_team}\n*Impacts:* {matched} impacts"
    elif payload.get("smoke"):
        title = payload.get("summary") or "SCA Monitor alert channel test"
        detail = f"*Channel:* {payload.get('channel_name', '-')}\n*Source:* {payload.get('source', '-')}\n*Generated:* {payload.get('generated_at', '-')}"
    else:
        risk = str(payload.get("risk_level") or "info")
        service = payload.get("service_name") or payload.get("service_id") or "Unknown service"
        advisory = payload.get("advisory_id") or "Unknown advisory"
        package = payload.get("package_name") or "unknown package"
        version = payload.get("resolved_version") or "unknown version"
        title = f"[{risk}] {service} - {advisory}"
        detail = f"*Advisory:* {advisory}\n*Package:* `{package}` `{version}`\n*Reason:* {payload.get('reason', '-')}"
    return {
        "text": title if not payload.get("smoke") else payload.get("summary", title),
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": detail[:3000]}},
        ],
        "metadata": {
            "event_type": "sca_monitor_alert",
            "event_payload": {
                "alert_event_id": payload.get("alert_event_id") or payload.get("smoke_id"),
                "alert_suppression_key": payload.get("alert_suppression_key"),
            },
        },
    }


def send_webhook(webhook_url: str, payload: dict, extra_headers: dict[str, str] | None = None) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "sca-monitor/0.1", **(extra_headers or {})},
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
