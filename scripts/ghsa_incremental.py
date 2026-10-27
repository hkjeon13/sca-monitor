#!/usr/bin/env python3
"""Import every GitHub page in the current modified window before advancing its cursor."""

import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.sca_monitor.advisory_sync import (
    GITHUB_ADVISORIES_API_URL,
    sync_github_advisories,
)
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main():
    app = ScaMonitorApp(load_settings(component="worker"))
    with app.db.connect() as conn:
        row = conn.execute(
            "SELECT cursor,last_success_at FROM advisory_sync_state WHERE source='GHSA'"
        ).fetchone()
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=30)
    if row:
        raw = row["cursor"] or row["last_success_at"]
        try:
            start = datetime.fromisoformat(str(raw).replace("Z", "+00:00")) - timedelta(
                days=1
            )
        except (ValueError, TypeError):
            pass
    params = {
        "sort": "updated",
        "direction": "asc",
        "per_page": 100,
        "modified": ">=" + start.date().isoformat(),
        "type": "reviewed",
    }
    url = GITHUB_ADVISORIES_API_URL + "?" + urlencode(params)
    payload = []
    seen = set()
    while url:
        if (
            url in seen
            or urlparse(url).hostname != "api.github.com"
            or urlparse(url).scheme != "https"
        ):
            raise RuntimeError("Invalid GitHub pagination URL")
        seen.add(url)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sca-monitor/0.2",
        }
        if os.getenv("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
        with urlopen(Request(url, headers=headers), timeout=60) as response:
            page = json.load(response)
            link = response.headers.get("Link", "")
        if not isinstance(page, list):
            raise TypeError("Invalid GitHub advisory response")
        payload.extend(page)
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = match.group(1) if match else None
    with tempfile.TemporaryDirectory(prefix="sca-ghsa-") as tmp:
        path = Path(tmp) / "advisories.json"
        path.write_text(json.dumps(payload))
        result = sync_github_advisories(app, json_path=path, limit=None)
    if not result.failed:
        app.record_advisory_sync(
            "GHSA",
            "ok",
            "modified-window",
            None,
            cursor=now.isoformat(),
            records_processed=result.processed,
        )
    print(json.dumps(result.__dict__, default=str), flush=True)
    return 1 if result.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
