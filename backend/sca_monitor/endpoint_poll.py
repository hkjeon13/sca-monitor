from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .app import ScaMonitorApp, fetch_json_endpoint


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
) -> EndpointPollResult:
    result = EndpointPollResult()
    fetcher = fetcher or fetch_json_endpoint
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
    return result
