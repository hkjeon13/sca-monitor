from __future__ import annotations

import socket
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable
from uuid import uuid4

from .app import ScaMonitorApp, fetch_json_endpoint, utcnow_after_seconds
from .db import utcnow


@dataclass
class EndpointPollResult:
    checked: int = 0
    succeeded: int = 0
    failed: int = 0
    snapshots_created_or_updated: int = 0


def poll_configured_endpoints(
    app: ScaMonitorApp,
    *,
    limit: int = 50,
    fetcher: Callable | None = None,
    worker_name: str = "default",
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 300,
    use_lock: bool = True,
) -> EndpointPollResult:
    owner = lock_owner or default_lock_owner()
    if use_lock:
        with endpoint_poll_lock(app, worker_name, owner, ttl_seconds=lock_ttl_seconds):
            return _poll_configured_endpoints(app, limit=limit, fetcher=fetcher, worker_name=worker_name)
    return _poll_configured_endpoints(app, limit=limit, fetcher=fetcher, worker_name=worker_name)


@contextmanager
def endpoint_poll_lock(app: ScaMonitorApp, worker_name: str, owner: str, ttl_seconds: int = 300):
    now = utcnow()
    expires_at = utcnow_after_seconds(ttl_seconds)
    with app.db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO endpoint_poll_state (worker_name, status, updated_at)
            VALUES (?, 'pending', ?)
            ON CONFLICT(worker_name) DO NOTHING
            """,
            (worker_name, now),
        )
        updated = conn.execute(
            """
            UPDATE endpoint_poll_state
            SET lock_owner = ?, lock_expires_at = ?, updated_at = ?
            WHERE worker_name = ?
              AND (lock_owner IS NULL OR lock_owner = ? OR lock_expires_at IS NULL OR lock_expires_at < ?)
            """,
            (owner, expires_at, now, worker_name, owner, now),
        ).rowcount
        if updated != 1:
            row = conn.execute(
                "SELECT lock_owner, lock_expires_at FROM endpoint_poll_state WHERE worker_name = ?",
                (worker_name,),
            ).fetchone()
            conn.execute(
                """
                UPDATE endpoint_poll_state
                SET lease_acquire_failures = lease_acquire_failures + 1,
                    last_error_at = ?,
                    last_error_message = ?,
                    updated_at = ?
                WHERE worker_name = ?
                """,
                (
                    now,
                    f"lock held by {row['lock_owner']} until {row['lock_expires_at']}",
                    now,
                    worker_name,
                ),
            )
            conn.commit()
            raise RuntimeError(f"{worker_name} endpoint poll lock is held by {row['lock_owner']} until {row['lock_expires_at']}")
    try:
        yield
    finally:
        with app.db.connect() as conn:
            conn.execute(
                """
                UPDATE endpoint_poll_state
                SET lock_owner = NULL, lock_expires_at = NULL, updated_at = ?
                WHERE worker_name = ? AND lock_owner = ?
                """,
                (utcnow(), worker_name, owner),
            )


def _poll_configured_endpoints(
    app: ScaMonitorApp,
    *,
    limit: int,
    fetcher: Callable | None,
    worker_name: str,
) -> EndpointPollResult:
    result = EndpointPollResult()
    fetcher = fetcher or fetch_json_endpoint
    try:
        with app.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT service_id, environment
                FROM services
                WHERE status_endpoint_url IS NOT NULL
                  AND status_endpoint_url != ''
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        for row in rows:
            result.checked += 1
            try:
                collected = app.collect_service_endpoint_payload(
                    row["service_id"],
                    {"environment": row["environment"]},
                    fetcher,
                )
                snapshot = dict(collected["payload"])
                snapshot.setdefault("source_type", "endpoint")
                pushed = app.push_snapshot(snapshot)
                result.snapshots_created_or_updated += pushed["impacts_created_or_updated"]
                result.succeeded += 1
            except Exception:
                result.failed += 1
        record_endpoint_poll_state(app, worker_name, result)
    except Exception as exc:
        record_endpoint_poll_state(app, worker_name, result, error_message=str(exc))
        raise
    return result


def record_endpoint_poll_state(
    app: ScaMonitorApp,
    worker_name: str,
    result: EndpointPollResult,
    error_message: str | None = None,
) -> None:
    now = utcnow()
    status = "error" if error_message else ("partial" if result.failed else "ok")
    with app.db.connect() as conn:
        conn.execute(
            """
            INSERT INTO endpoint_poll_state (
                worker_name, status, last_success_at, last_error_at, last_error_message,
                checked_count, succeeded_count, failed_count, snapshots_created_or_updated, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(worker_name) DO UPDATE SET
                status=excluded.status,
                last_success_at=excluded.last_success_at,
                last_error_at=excluded.last_error_at,
                last_error_message=excluded.last_error_message,
                checked_count=excluded.checked_count,
                succeeded_count=excluded.succeeded_count,
                failed_count=excluded.failed_count,
                snapshots_created_or_updated=excluded.snapshots_created_or_updated,
                updated_at=excluded.updated_at
            """,
            (
                worker_name,
                status,
                now if not error_message else None,
                now if error_message else None,
                error_message,
                result.checked,
                result.succeeded,
                result.failed,
                result.snapshots_created_or_updated,
                now,
            ),
        )


def default_lock_owner() -> str:
    return f"endpoint-poll:{socket.gethostname()}:{uuid4()}"
